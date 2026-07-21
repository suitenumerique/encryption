/**
 * Per-request proof of identity-key possession, modelled on the well-trodden
 * DPoP pattern (RFC 9449) and the JWS compact serialization (RFC 7515): a small
 * signed token, sent in a header, that binds THIS request (method + path) to a
 * fresh timestamp and is signed by the caller's identity key.
 *
 * The token is a compact JWS `base64url(header).base64url(claims).base64url(sig)`:
 *   header = { alg: "EdDSA", typ: "vault-req+jws" }
 *   claims = { sub, htm, htu, bh, iat, exp }   // method, path, BODY DIGEST, window
 *   sig    = Ed25519(identitySecretKey, "header.claims")
 *
 * `bh` is base64url(SHA-256(rawBody)) — the same body-digest idea as AWS SigV4's
 * payload hash and RFC 9421's `Content-Digest`. Without it, a captured signature
 * could be replayed against the same method+path with a swapped body; with it,
 * any change to the body invalidates the proof.
 *
 * One deliberate deviation from DPoP: we do NOT embed (and trust) the public key
 * in the header. The server resolves the caller's identity key from the registry
 * and verifies against THAT, so a token can only authenticate as a key the user
 * actually registered, never as a self-asserted one.
 *
 * Replay: the covered method+path+body-digest stop a signature from being reused
 * on a different endpoint or with different data, and the short validity window
 * bounds reuse in time. We keep no server-side seen-token cache: the reads this
 * gates are idempotent and the writes carry their own monotonic-revision replay
 * protection, so a bounded time window is sufficient (see architecture.md §7.1).
 */
import sodium from 'libsodium-wrappers-sumo';

import { ensureSodium } from '@encryption/src/crypto/encryption';
import { importPublicKeyFromBytes } from '@encryption/src/crypto/encryption-backup';
import { signDetached, verifyDetached } from '@encryption/src/crypto/signature';

/** HTTP header (lowercase, as Fastify normalizes) carrying the compact JWS. */
export const REQUEST_SIG_HEADER = 'x-signature';
const HEADER_TYP = 'vault-req+jws';
const HEADER_ALG = 'EdDSA';
/** Max self-asserted lifetime of a proof, and the future-skew tolerance. */
export const REQUEST_SIG_MAX_AGE_SECONDS = 120;
export const REQUEST_SIG_SKEW_SECONDS = 30;

interface ProofClaims {
  sub: string; // INTERNAL user id the proof is made for (must match the JWT-resolved internal id, never an OIDC sub)
  htm: string; // HTTP method, uppercase
  htu: string; // request path (no query string)
  bh: string; // base64url(SHA-256(rawBody)); the digest of the exact request body
  iat: number; // issued-at, epoch seconds
  exp: number; // expiry, epoch seconds
}

const B64URL = () => sodium.base64_variants.URLSAFE_NO_PADDING;

function encodeStr(s: string): string {
  return sodium.to_base64(sodium.from_string(s), B64URL());
}

function encodeBytes(b: Uint8Array): string {
  return sodium.to_base64(b, B64URL());
}

// Digest of the exact request body string ('' for a bodyless request). Both
// sides must hash the SAME bytes the client puts on the wire.
function bodyDigest(body: string): string {
  return sodium.to_base64(sodium.crypto_hash_sha256(sodium.from_string(body)), B64URL());
}

// Only the path matters; a query string (if any) is not part of the covered URI,
// so both sides strip it before signing/verifying.
function normalizePath(path: string): string {
  const q = path.indexOf('?');

  return q === -1 ? path : path.slice(0, q);
}

/**
 * Client side (vault iframe): build and sign a proof for one outgoing request.
 * `identitySecretKey` is the RAW Ed25519 secret (as stored in the vault state and
 * used by `signManifest`), `nowSeconds` is the current epoch time in seconds.
 */
export async function signRequestProof(params: {
  method: string;
  path: string;
  userId: string;
  identitySecretKey: Uint8Array;
  nowSeconds: number;
  body?: string;
}): Promise<string> {
  await ensureSodium();

  const header = { alg: HEADER_ALG, typ: HEADER_TYP };
  const claims: ProofClaims = {
    sub: params.userId,
    htm: params.method.toUpperCase(),
    htu: normalizePath(params.path),
    bh: bodyDigest(params.body ?? ''),
    iat: params.nowSeconds,
    exp: params.nowSeconds + REQUEST_SIG_MAX_AGE_SECONDS,
  };

  const signingInput = `${encodeStr(JSON.stringify(header))}.${encodeStr(JSON.stringify(claims))}`;
  const signature = await signDetached(sodium.from_string(signingInput), params.identitySecretKey);

  return `${signingInput}.${encodeBytes(signature)}`;
}

// Split a compact JWS into its verifiable parts, or null if malformed.
function parseProof(token: string): { header: unknown; claims: ProofClaims; signingInput: string; signature: Uint8Array } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(sodium.to_string(sodium.from_base64(parts[0], B64URL())));
    const claims = JSON.parse(sodium.to_string(sodium.from_base64(parts[1], B64URL()))) as ProofClaims;
    const signature = sodium.from_base64(parts[2], B64URL());

    return { header, claims, signingInput: `${parts[0]}.${parts[1]}`, signature };
  } catch {
    return null;
  }
}

/**
 * Read the (UNVERIFIED) subject from a proof, so a JWT-less request can tell the
 * server which user to verify against. Safe because the signature is verified
 * separately against that user's registered key: a forged subject simply won't
 * verify. Returns null on a malformed token.
 */
export async function readProofSubject(token: string): Promise<string | null> {
  await ensureSodium();

  const parsed = parseProof(token);

  return parsed && typeof parsed.claims?.sub === 'string' ? parsed.claims.sub : null;
}

/**
 * Server side: verify a proof against the request it accompanies and the set of
 * identity public keys the server is willing to accept for this user. The keys
 * are the DB WIRE blobs (`[version][ed25519]`); each is stripped with
 * `importPublicKeyFromBytes` exactly as manifest verification does. Returns true
 * on the first match. Never throws.
 */
export async function verifyRequestProof(params: {
  token: string;
  method: string;
  path: string;
  userId: string;
  acceptableIdentityWireKeys: Uint8Array[];
  nowSeconds: number;
  body?: string;
}): Promise<boolean> {
  await ensureSodium();

  const parsed = parseProof(params.token);
  if (!parsed) return false;

  const header = parsed.header as { alg?: unknown; typ?: unknown };
  if (header?.alg !== HEADER_ALG || header?.typ !== HEADER_TYP) return false;

  const c = parsed.claims;
  if (typeof c?.sub !== 'string' || typeof c?.htm !== 'string' || typeof c?.htu !== 'string' || typeof c?.bh !== 'string') return false;
  if (typeof c.iat !== 'number' || typeof c.exp !== 'number') return false;

  // Bind the proof to exactly this request, body, and user.
  if (c.sub !== params.userId) return false;
  if (c.htm !== params.method.toUpperCase()) return false;
  if (c.htu !== normalizePath(params.path)) return false;
  if (c.bh !== bodyDigest(params.body ?? '')) return false;

  // Freshness: not issued in the future (beyond skew), not expired, and the
  // client cannot self-assert a window longer than the server's cap.
  if (c.iat > params.nowSeconds + REQUEST_SIG_SKEW_SECONDS) return false;
  if (c.exp <= params.nowSeconds) return false;
  if (c.exp - c.iat > REQUEST_SIG_MAX_AGE_SECONDS) return false;

  const message = sodium.from_string(parsed.signingInput);

  for (const wire of params.acceptableIdentityWireKeys) {
    let raw: Uint8Array;
    try {
      raw = importPublicKeyFromBytes(wire);
    } catch {
      continue; // malformed stored key: skip, don't throw
    }

    if (await verifyDetached(parsed.signature, message, raw)) return true;
  }

  return false;
}
