/**
 * Device approval: an enrolled device forwards the VRK to a new one.
 *
 * The new device generates an ephemeral X-Wing key pair and registers its public
 * key with the server under a `requestId`. It then shows a 128-bit DECIMAL
 * fingerprint of that key, both as a QR (scanned by camera) and as digits to type
 * when there is no camera. Either way the enrolled device fetches the pending key
 * from the server and refuses to wrap the VRK unless that key's decimal
 * fingerprint matches the one carried over out-of-band. 128 bits is well beyond a
 * grinding server's reach (2^128), so it cannot substitute a colliding key.
 *
 * The VRK is a 32-byte symmetric key, so wrapping reuses the same X-Wing path the
 * vault already uses to wrap document keys for recipients.
 */
import sodium from 'libsodium-wrappers-sumo';

import { type HybridSecretKey, decryptSymmetricKeyForUser, encryptSymmetricKeyForUsers } from '@encryption/src/crypto';
import { base64ToUint8, importPublicKeyFromBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { DOMAIN_DEVICE_PAIRING_FINGERPRINT, DOMAIN_KEM_DEVICE_BOOTSTRAP } from '@encryption/src/shared/crypto-domains';
import { computeDecimalFingerprint, normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

const DEVICE_ID = 'device';

// 128 bits, so a malicious server cannot grind a substitute key with a colliding
// fingerprint (2^128), while staying all-digits for easy manual entry. Its own
// domain: a pairing code can never equal an identity fingerprint.
export async function deviceKeyDecimalFingerprint(devicePublicKeyB64: string): Promise<string> {
  return computeDecimalFingerprint(DOMAIN_DEVICE_PAIRING_FINGERPRINT, base64ToUint8(devicePublicKeyB64));
}

// The bootstrap material forwarded to a new device: the VRK and the identity
// secret key. Both are needed and non-redundant: the VRK DECRYPTS the sealed
// vault, and the identity key AUTHENTICATES the new device's very first
// `GET /vault/items` pull (a covered route), which it must make to obtain the
// vault that contains that same identity key.
//
// Encoded as a small JSON object (each key base64) BEFORE wrapping, deliberately
// self-describing and extensible: adding a future field is just another JSON key,
// with no positional/offset parsing to get wrong.
interface DeviceBootstrap {
  vrk: Uint8Array;
  identitySecretKey: Uint8Array;
}

function encodeBootstrap(b: DeviceBootstrap): Uint8Array {
  return sodium.from_string(JSON.stringify({ vrk: uint8ToBase64(b.vrk), identity_secret_key: uint8ToBase64(b.identitySecretKey) }));
}

function decodeBootstrap(bytes: Uint8Array): DeviceBootstrap {
  const parsed = JSON.parse(sodium.to_string(bytes)) as { vrk?: string; identity_secret_key?: string };

  if (typeof parsed.vrk !== 'string' || typeof parsed.identity_secret_key !== 'string') {
    throw new Error('Malformed device bootstrap payload');
  }

  return { vrk: base64ToUint8(parsed.vrk), identitySecretKey: base64ToUint8(parsed.identity_secret_key) };
}

/**
 * Enrolled device: wrap the bootstrap material (VRK + identity secret key) to the
 * new device's public key, which the server returned for the pending request.
 * `expectedDecimal` is the fingerprint carried over out-of-band (QR scan or
 * typed). We refuse (return null) unless the server key's decimal fingerprint
 * matches it, which is the "server swapped the key" case.
 */
export async function wrapBootstrapForNewDevice(
  vrk: Uint8Array,
  identitySecretKey: Uint8Array,
  devicePublicKeyB64: string,
  expectedDecimal: string
): Promise<Uint8Array | null> {
  await sodium.ready;

  const normalized = normalizeDecimalFingerprint(expectedDecimal);
  if (normalized.length === 0) return null;

  if ((await deviceKeyDecimalFingerprint(devicePublicKeyB64)) !== normalized) return null;

  const publicKey = importPublicKeyFromBase64(devicePublicKeyB64);
  const wrapped = await encryptSymmetricKeyForUsers(
    encodeBootstrap({ vrk, identitySecretKey }),
    { [DEVICE_ID]: publicKey },
    DOMAIN_KEM_DEVICE_BOOTSTRAP
  );

  return wrapped[DEVICE_ID];
}

/** New device: unwrap the forwarded bootstrap material with the ephemeral secret key. */
export async function unwrapBootstrapOnNewDevice(wrapped: Uint8Array, ephemeralSecretKey: HybridSecretKey): Promise<DeviceBootstrap> {
  await sodium.ready;

  return decodeBootstrap(await decryptSymmetricKeyForUser(ephemeralSecretKey, wrapped, DOMAIN_KEM_DEVICE_BOOTSTRAP));
}
