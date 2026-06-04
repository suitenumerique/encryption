import { BROADCAST_KEYS_CHANGED, BROADCAST_KEYS_DESTROYED, MSG_VAULT_READY } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { setupMessageHandler } from '@encryption/src/vault/message-handler';
import { initOriginGuard, validateIframeContext } from '@encryption/src/vault/origin-guard';

/**
 * Runtime config injected by the server into bridge.html.
 * In dev mode, falls back to defaults for localhost.
 */
interface VaultConfig {
  allowedOrigins: string[];
  interfaceOrigin: string;
}

const runtimeConfig = (window as unknown as { __ENCRYPTION_VAULT_CONFIG__?: VaultConfig }).__ENCRYPTION_VAULT_CONFIG__;

const ALLOWED_ORIGINS: string[] = runtimeConfig?.allowedOrigins ?? [];

const INTERFACE_ORIGIN: string | null = runtimeConfig?.interfaceOrigin ?? null;

try {
  validateIframeContext();
} catch {
  if (import.meta.env.DEV) {
    console.warn('Vault loaded outside of iframe - allowed in development mode');
  } else {
    throw new Error('Vault must be loaded in an iframe');
  }
}

initOriginGuard(ALLOWED_ORIGINS, INTERFACE_ORIGIN);
setupMessageHandler();

// Notify the parent frame that the vault is ready.
// The ready message is non-sensitive (just a signal), so we use '*'
// to avoid console errors from origin mismatches — the vault doesn't
// know which specific allowed origin loaded it.
// The VaultClient verifies the message origin on its side.
if (window.parent !== window) {
  window.parent.postMessage({ type: MSG_VAULT_READY }, '*');
}

// Forward BroadcastChannel messages to the parent so cross-tab
// notifications (keys-changed, keys-destroyed) reach the hosting product.
// Using the shared instance ensures that messages sent BY this vault
// are NOT received here (per BroadcastChannel spec), so only other tabs trigger this.
const bc = getVaultBroadcastChannel();
if (bc) {
  bc.onmessage = (event) => {
    const msg = event.data as { type: string };
    if (msg.type === BROADCAST_KEYS_CHANGED || msg.type === BROADCAST_KEYS_DESTROYED) {
      if (window.parent !== window) {
        window.parent.postMessage({ type: `vault:${msg.type}` }, '*');
      }
    }
  };
}

// Register the service worker for cache management and version updates.
// Skip in dev mode — the SW precaches vault files which conflicts with
// Vite's on-the-fly module transformation.
if ('serviceWorker' in navigator && !import.meta.env.DEV) {
  navigator.serviceWorker.register('/sw.js').catch(() => {
    // SW registration may fail in some iframe contexts — vault still works without it
  });
}
