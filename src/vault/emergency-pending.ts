/**
 * One-shot check for actionable emergency-access state, pushed to the product
 * page so the SDK can surface it (a pending designation to accept, a running
 * recovery request to refuse). Rides the identity-signed data plane: the
 * SDK/products never hold a JWT, but a device with a vault holds the identity
 * key, which is exactly the population that can act from a product page.
 *
 * At most one check per (user, page load): this is a courtesy surface, the
 * load-bearing channel is email.
 */
import { REQUEST_SIG_HEADER } from '@encryption/src/crypto/request-proof';
import { MSG_VAULT_EMERGENCY_PENDING } from '@encryption/src/shared/constants';
import { createRequestSigner } from '@encryption/src/vault/operations/request-signer';
import { deriveStoredKeyPair, loadVault } from '@encryption/src/vault/vault-keys';

const API_BASE = '';
const PENDING_PATH = '/api/emergency-access/pending';

export interface EmergencyPendingState {
  invitations: number;
  recovery_requests: number;
}

const checkedUsers = new Set<string>();

/** For tests: forget the per-page-load memory. */
export function resetEmergencyPendingCheck(): void {
  checkedUsers.clear();
}

export async function checkEmergencyPending(userId: string, post: (message: unknown) => void): Promise<void> {
  if (checkedUsers.has(userId)) return;
  checkedUsers.add(userId);

  try {
    const loaded = await loadVault(userId);
    if (!loaded) return; // no vault on this device: nothing to sign with, emails cover it

    const pair = deriveStoredKeyPair(loaded.state);
    if (!pair) return;

    const sign = createRequestSigner(pair.signatureSecretKey, userId);
    const signature = await sign('GET', PENDING_PATH);

    const res = await fetch(`${API_BASE}${PENDING_PATH}`, { headers: { [REQUEST_SIG_HEADER]: signature } });
    if (!res.ok) return;

    const state = (await res.json()) as EmergencyPendingState;
    if (state.invitations === 0 && state.recovery_requests === 0) return;

    // Only a routing signal crosses to the product: which prompt to lead with,
    // never who or when (the interface fetches that itself over its JWT).
    post({ type: MSG_VAULT_EMERGENCY_PENDING, payload: { recovery: state.recovery_requests > 0, invitation: state.invitations > 0 } });
  } catch {
    // Courtesy only: never let this surface as an error to the product.
  }
}
