import { base64ToUint8, encodeKeyRegistrationPayload, exportPublicKeyAsBase64, signDetached, uint8ToBase64 } from '@encryption/src/crypto';
import { getStoredKeyBundle } from '@encryption/src/vault/operations/key-management';

/**
 * Produce the signed registration record the UI submits to the server.
 *
 * The vault is the only place the signature secret key lives, so it is the
 * only place the binding signature can be produced. Given the `version` and
 * `createdAt` the caller intends to register (version = previous active
 * version + 1, or 1 for a first key), the vault:
 *   1. loads both public keys,
 *   2. builds the canonical registration payload (see key-registration.ts),
 *   3. signs it with the identity (signature) secret key.
 *
 * The server re-verifies this signature before persisting, and so does every
 * other user's vault at share time. Because the signature covers `version` and
 * `createdAtMillis`, neither the server nor a database attacker can alter them
 * after the fact without invalidating the record.
 */
export async function handleSignKeyRegistration(
  userId: string,
  payload: { version: number; createdAtMillis: number }
): Promise<{
  encryptionPublicKey: string;
  signaturePublicKey: string;
  version: number;
  createdAtMillis: number;
  keyBindingSignature: string;
}> {
  const bundle = await getStoredKeyBundle(userId);

  const encryptionPublicKey = exportPublicKeyAsBase64(bundle.encryption.publicKey);
  const signaturePublicKey = exportPublicKeyAsBase64(bundle.signature.publicKey);

  // Sign over the exact wire blobs (version-prefixed, the full base64-decoded
  // bytes the server stores and returns), so verification never has to
  // re-derive them — it just base64-decodes the same strings.
  const encryptionPublicKeyWire = base64ToUint8(encryptionPublicKey);
  const signaturePublicKeyWire = base64ToUint8(signaturePublicKey);

  const message = encodeKeyRegistrationPayload({
    userId,
    version: payload.version,
    createdAtMillis: payload.createdAtMillis,
    encryptionPublicKeyWire,
    signaturePublicKeyWire,
  });

  const signature = await signDetached(message, bundle.signature.secretKey);

  return {
    encryptionPublicKey,
    signaturePublicKey,
    version: payload.version,
    createdAtMillis: payload.createdAtMillis,
    keyBindingSignature: uint8ToBase64(signature),
  };
}
