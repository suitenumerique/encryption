/**
 * Core cryptographic operations using libsodium (WASM).
 *
 * Asymmetric: X-Wing hybrid KEM — X25519 + ML-KEM-768, with the
 * SHA3-256 ciphertext-binding combiner from
 * IRTF draft-connolly-cfrg-xwing-kem. Combiner, key generation,
 * encapsulation and decapsulation all live inside libsodium's
 * crypto_kem_xwing_* functions; we just call them.
 *
 * Symmetric: XChaCha20-Poly1305 (crypto_secretbox). Quantum-safe.
 *   - 256-bit keys, 192-bit random nonces (safe with random generation).
 *
 * Versioning: every serialized binary blob (public key for the wire,
 * wrapped symmetric key, encrypted content) starts with a single
 * CRYPTO_VERSION byte. Bumping it adds a legacy decode path side-by-side
 * so older blobs stay readable without ambiguity.
 */
import sodium from 'libsodium-wrappers-sumo';

import { CRYPTO_VERSION } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

// Encode/decode length fields with explicit little-endian byte order.
// Using DataView instead of typed arrays avoids platform endianness issues
// (typed arrays use the platform's native byte order, which could differ
// between the encrypting and decrypting device).

export function writeUint16LE(value: number): Uint8Array {
  const buf = new ArrayBuffer(2);
  new DataView(buf).setUint16(0, value, true);
  return new Uint8Array(buf);
}

export function readUint16LE(bytes: Uint8Array): number {
  return new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, true);
}

export function writeUint32LE(value: number): Uint8Array {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, value, true);
  return new Uint8Array(buf);
}

export function readUint32LE(bytes: Uint8Array): number {
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
}

// Ensure sodium is ready before any operation
let sodiumReady: Promise<void> | null = null;

export function ensureSodium(): Promise<void> {
  if (!sodiumReady) {
    sodiumReady = sodium.ready;
  }

  return sodiumReady;
}

// ============================================================================
// Key types
// ============================================================================

// X-Wing keys are opaque blobs of fixed size:
//   public  key: crypto_kem_xwing_PUBLICKEYBYTES  (1216 B)
//   secret  key: crypto_kem_xwing_SECRETKEYBYTES  (2464 B)
//   ciphertext : crypto_kem_xwing_CIPHERTEXTBYTES (1120 B)
// We never inspect or split them — the construction is handled by libsodium.
// "Hybrid" in the type name refers to X-Wing being a hybrid KEM (classical +
// post-quantum), not to a manual two-slot composition.
export type HybridPublicKey = Uint8Array;
export type HybridSecretKey = Uint8Array;

export interface HybridKeyPair {
  publicKey: HybridPublicKey;
  secretKey: HybridSecretKey;
}

// ============================================================================
// Asymmetric: X-Wing key pair generation
// ============================================================================

export async function generateUserKeyPair(): Promise<HybridKeyPair> {
  await ensureSodium();

  const kp = sodium.crypto_kem_xwing_keypair();

  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey,
  };
}

// ============================================================================
// Asymmetric: encapsulate / decapsulate
// ============================================================================

/**
 * Encapsulate a shared secret for a recipient using their X-Wing public key.
 * Returns the shared secret (32 bytes) and the X-Wing ciphertext (1120 bytes).
 */
export async function hybridEncapsulate(recipientPublicKey: HybridPublicKey): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
  await ensureSodium();

  const r = sodium.crypto_kem_xwing_enc(recipientPublicKey);

  return { sharedSecret: r.sharedSecret, ciphertext: r.ciphertext };
}

/**
 * Decapsulate a shared secret using the local X-Wing secret key.
 */
export async function hybridDecapsulate(secretKey: HybridSecretKey, ciphertext: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.crypto_kem_xwing_dec(ciphertext, secretKey);
}

// ============================================================================
// Symmetric: XChaCha20-Poly1305
// ============================================================================

export async function generateSymmetricKey(): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.crypto_secretbox_keygen();
}

/**
 * Encrypt content with a symmetric key (XChaCha20-Poly1305).
 * Format: [version:1][nonce:24][ciphertext:n].
 */
export async function encryptContent(content: Uint8Array, symmetricKey: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES); // 24 bytes
  const ciphertext = sodium.crypto_secretbox_easy(content, nonce, symmetricKey);

  const result = new Uint8Array(1 + nonce.length + ciphertext.length);
  result[0] = CRYPTO_VERSION;
  result.set(nonce, 1);
  result.set(ciphertext, 1 + nonce.length);

  return result;
}

/**
 * Decrypt content with a symmetric key (XChaCha20-Poly1305).
 * Expects [version:1][nonce:24][ciphertext:n].
 */
export async function decryptContent(encryptedContent: Uint8Array, symmetricKey: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  const minLen = 1 + sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES;

  if (encryptedContent.length < minLen) {
    throw new VaultError(VaultErrorCode.CIPHERTEXT_TOO_SHORT, 'Encrypted content is too short to be valid');
  }

  const version = encryptedContent[0];

  if (version !== CRYPTO_VERSION) {
    throw new VaultError(VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION, `Unsupported crypto version ${version}`);
  }

  const nonce = encryptedContent.slice(1, 1 + sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = encryptedContent.slice(1 + sodium.crypto_secretbox_NONCEBYTES);

  // libsodium throws "wrong secret key for the given ciphertext" on AEAD
  // verification failure — surface that as our stable code so consumers
  // never have to regex on the message. Re-throw anything else verbatim.
  try {
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, symmetricKey);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/wrong secret key/i.test(msg)) {
      throw new VaultError(VaultErrorCode.WRONG_SECRET_KEY, msg);
    }
    throw err;
  }
}

// ============================================================================
// Multi-user: encrypt a symmetric key for multiple recipients
// ============================================================================

/**
 * Encrypt a symmetric key for multiple users using their X-Wing public keys.
 * Returns a map of userId → wrapped key blob.
 *
 * Wrap format: [version:1][kemCtLen:2][kemCt:kemCtLen][encryptedSymKey:n]
 * (the inner encryptedSymKey already carries its own version + nonce.)
 */
export async function encryptSymmetricKeyForUsers(
  symmetricKey: Uint8Array,
  usersPublicKeys: Record<string, HybridPublicKey>
): Promise<Record<string, Uint8Array>> {
  const entries = Object.entries(usersPublicKeys);

  const results = await Promise.all(
    entries.map(async ([userId, publicKey]) => {
      const { sharedSecret, ciphertext: kemCiphertext } = await hybridEncapsulate(publicKey);
      const encrypted = await encryptContent(symmetricKey, sharedSecret);

      const kemLen = writeUint16LE(kemCiphertext.length);
      const combined = new Uint8Array(1 + 2 + kemCiphertext.length + encrypted.length);
      combined[0] = CRYPTO_VERSION;
      combined.set(kemLen, 1);
      combined.set(kemCiphertext, 3);
      combined.set(encrypted, 3 + kemCiphertext.length);

      return [userId, combined] as const;
    })
  );

  return Object.fromEntries(results);
}

/**
 * Decrypt a symmetric key that was encrypted for the local user.
 */
export async function decryptSymmetricKeyForUser(secretKey: HybridSecretKey, encryptedKey: Uint8Array): Promise<Uint8Array> {
  if (encryptedKey.length < 3) {
    throw new VaultError(VaultErrorCode.CIPHERTEXT_TOO_SHORT, 'Encrypted key is too short to be valid');
  }

  const version = encryptedKey[0];

  if (version !== CRYPTO_VERSION) {
    throw new VaultError(VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION, `Unsupported crypto version ${version}`);
  }

  // Parse: [version:1][kemCtLen:2][kemCt][encryptedSymKey]
  const kemLen = readUint16LE(encryptedKey.slice(1, 3));
  const kemCiphertext = encryptedKey.slice(3, 3 + kemLen);
  const encryptedSymKey = encryptedKey.slice(3 + kemLen);

  const sharedSecret = await hybridDecapsulate(secretKey, kemCiphertext);

  return decryptContent(encryptedSymKey, sharedSecret);
}
