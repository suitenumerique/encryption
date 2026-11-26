/**
 * Digital signatures using libsodium (Ed25519, `crypto_sign_*`).
 *
 * The signature key pair is the user's IDENTITY. Unlike the encryption key
 * pair (X-Wing, used to wrap symmetric keys), the signature key is what other
 * users verify out-of-band — via a QR code or by reading the public-key
 * fingerprint aloud. It never wraps content; it only signs:
 *   - the binding that ties an encryption public key to this identity
 *     (see src/crypto/key-registration.ts), and
 *   - proof-of-possession challenges during registration.
 *
 * Why Ed25519 (classical, not post-quantum): libsodium does not yet expose a
 * stable post-quantum signature primitive (ML-DSA / SLH-DSA). Introducing a
 * hand-rolled PQ signature would add risk without a vetted implementation, so
 * the identity key is classical for now. The wire format carries a leading
 * version byte (CRYPTO_VERSION) exactly like the encryption public key, so a
 * future swap to a hybrid/PQ signature can dispatch on the prefix and keep old
 * identities verifiable side-by-side.
 *
 * Sizes (libsodium): public 32 B, secret 64 B, detached signature 64 B.
 */
import sodium from 'libsodium-wrappers-sumo';

import { ensureSodium } from '@encryption/src/crypto/encryption';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

// Opaque fixed-size blobs, mirroring the Hybrid* types from encryption.ts.
export type SignaturePublicKey = Uint8Array;
export type SignatureSecretKey = Uint8Array;

export interface SignatureKeyPair {
  publicKey: SignaturePublicKey;
  secretKey: SignatureSecretKey;
}

export async function generateSignatureKeyPair(): Promise<SignatureKeyPair> {
  await ensureSodium();

  const kp = sodium.crypto_sign_keypair();

  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey,
  };
}

/**
 * Produce a 64-byte detached Ed25519 signature over `message` with the
 * identity secret key.
 */
export async function signDetached(message: Uint8Array, secretKey: SignatureSecretKey): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.crypto_sign_detached(message, secretKey);
}

/**
 * Verify a detached Ed25519 signature. Returns a boolean instead of throwing
 * so callers can branch on a forged/incoherent registry entry rather than
 * having to catch — the "this looks tampered, warn the user" path is a normal
 * outcome, not an exceptional one.
 */
export async function verifyDetached(signature: Uint8Array, message: Uint8Array, publicKey: SignaturePublicKey): Promise<boolean> {
  await ensureSodium();

  // libsodium throws if the public key has the wrong length; treat any such
  // malformed input as a failed verification rather than letting it escape.
  if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES || signature.length !== sodium.crypto_sign_BYTES) {
    return false;
  }

  try {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Guard that a decoded signature public key has the expected Ed25519 length.
 * Used at trust boundaries (server registration, registry verification) where
 * a malformed key should surface as a clear error rather than a libsodium
 * throw deep in a verify call.
 */
export async function assertValidSignaturePublicKey(publicKey: SignaturePublicKey): Promise<void> {
  await ensureSodium();

  if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new VaultError(VaultErrorCode.INVALID_SIGNATURE_KEY, `Signature public key must be ${sodium.crypto_sign_PUBLICKEYBYTES} bytes`);
  }
}
