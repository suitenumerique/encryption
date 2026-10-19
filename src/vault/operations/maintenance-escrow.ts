/**
 * The deployment's maintenance escrow key, as the vault sees it.
 *
 * The server puts the configured public key in the runtime-config data block, at
 * the same trust level as the allowed origins. It is parsed once: a malformed key
 * is a deployment error the server already refuses at boot, so here it only
 * guards against a tampered document and fails every wrap rather than silently
 * escrowing nothing.
 *
 * Never a recipient: the key is appended by the wrap operations themselves, after
 * the recipient trust gate has run, and returned in a field of its own. A product
 * cannot inject it, remove it, or make the vault wrap for another key.
 */
import { type HybridPublicKey, parseMaintenancePublicKey } from '@encryption/src/crypto';
import { runtimeConfig } from '@encryption/src/vault/runtime-config';

let parsed: HybridPublicKey | null | undefined;

export function getMaintenancePublicKey(): HybridPublicKey | null {
  if (parsed === undefined) {
    const base64 = runtimeConfig.maintenanceEscrowPublicKey;
    parsed = base64 ? parseMaintenancePublicKey(base64) : null;
  }

  return parsed;
}
