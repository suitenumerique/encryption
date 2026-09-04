import {
  BROADCAST_KEYS_CHANGED,
  BROADCAST_KEYS_DESTROYED,
  MSG_VAULT_READY,
  VAULT_SERVICE_WORKER_PATH,
  VAULT_TRUSTED_TYPES_POLICY,
} from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { setupMessageHandler } from '@encryption/src/vault/message-handler';
import { initOriginGuard, validateIframeContext } from '@encryption/src/vault/origin-guard';
import { runtimeConfig } from '@encryption/src/vault/runtime-config';
import { clearSymmetricKeyCache } from '@encryption/src/vault/symmetric-key-cache';

/**
 * Runtime config injected by the server into bridge.html.
 * In dev mode, falls back to defaults for localhost.
 */
const ALLOWED_ORIGINS: string[] = runtimeConfig.allowedOrigins ?? [];

const INTERFACE_ORIGIN: string | null = runtimeConfig.interfaceOrigin ?? null;

try {
  validateIframeContext();
} catch {
  // Revealing the warning used to be an inline <script> in bridge.html; doing it here
  // keeps `script-src` a bare `'self'` with nothing inline to authorize.
  const accessError = document.getElementById('access-error');

  if (accessError) accessError.style.display = 'block';

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
      // Another tab changed/destroyed the keys, so THIS vault's decrypted-key
      // cache may now be stale — drop it before forwarding the notification.
      clearSymmetricKeyCache();

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
  const policy = window.trustedTypes?.createPolicy(VAULT_TRUSTED_TYPES_POLICY, {
    createScriptURL: (url) => {
      if (url !== VAULT_SERVICE_WORKER_PATH) {
        throw new TypeError(`the vault Trusted Types policy only produces ${VAULT_SERVICE_WORKER_PATH}`);
      }

      return url;
    },
  });

  const scriptUrl = policy ? policy.createScriptURL(VAULT_SERVICE_WORKER_PATH) : VAULT_SERVICE_WORKER_PATH;

  navigator.serviceWorker.register(scriptUrl as string & TrustedScriptURL).catch(() => {
    // SW registration may fail in some iframe contexts — vault still works without it
  });
}
