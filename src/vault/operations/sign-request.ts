/**
 * Sign one outgoing covered request with the vault's identity key, so the
 * interface (which owns the OIDC token but NOT the identity key) can attach an
 * `X-Signature` to its own JWT-authenticated calls (change-phrase, device
 * approval). Privileged: only the interface origin may ask for a signature.
 *
 * The interface must sign the EXACT method + path it is about to call, and use
 * the signature promptly (it carries a short validity window). We never sign a
 * body: the covered writes carry their own field-level identity signatures, and
 * the transport proof only authenticates "this is the account's device".
 */
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { createRequestSigner } from '@encryption/src/vault/operations/request-signer';
import { loadVault } from '@encryption/src/vault/vault-keys';

export async function handleSignRequest(userId: string, payload: { method: string; path: string; body?: string }): Promise<{ signature: string }> {
  const loaded = await loadVault(userId);

  if (!loaded) {
    throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No vault on this device to sign a request.');
  }

  const identity = activeIdentity(loaded.state);

  if (!identity) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No active identity to sign a request.');
  }

  const sign = createRequestSigner(base64ToUint8(identity.signatureSecretKey), userId);

  // The caller passes the EXACT body string it will send, so the digest matches.
  return { signature: await sign(payload.method, payload.path, payload.body) };
}
