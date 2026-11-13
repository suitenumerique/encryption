/**
 * Builds a per-request signer bound to one identity key + user, for the vault's
 * outgoing calls to covered server routes. Kept tiny and separate so both the
 * sync runner and the device-adoption pull share the exact same construction.
 */
import { signRequestProof } from '@encryption/src/crypto/request-proof';

export type RequestSigner = (method: string, path: string, body?: string) => Promise<string>;

export function createRequestSigner(identitySecretKey: Uint8Array, userId: string): RequestSigner {
  return (method, path, body) => signRequestProof({ method, path, body, userId, identitySecretKey, nowSeconds: Math.floor(Date.now() / 1000) });
}
