import { useCallback, useEffect, useRef, useState } from 'react';

import {
  MSG_VAULT_APPROVE_DEVICE,
  MSG_VAULT_CHANGE_RECOVERY_PHRASE,
  MSG_VAULT_COMMIT_STAGED,
  MSG_VAULT_COMPLETE_DEVICE_APPROVAL,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_PREPARE_ONBOARDING,
  MSG_VAULT_REACTIVATE,
  MSG_VAULT_READY,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESTORE_FROM_PHRASE,
  MSG_VAULT_RESULT,
  MSG_VAULT_SIGN_KEY_REGISTRATION,
  MSG_VAULT_START_DEVICE_APPROVAL,
  MSG_VAULT_SYNC,
  MSG_VAULT_UNCOMMIT_STAGED,
} from '@encryption/src/shared/constants';
import type { VaultResponse } from '@encryption/src/shared/schemas/post-message';
import type { VaultItemWire, VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import { VaultError, type VaultErrorCode } from '@encryption/src/shared/vault-error';

interface UseEncryptionOptions {
  vaultUrl: string;
}

/** The vault half of the atomic-bootstrap body, plus the phrase to show once. */
export interface OnboardingBundle {
  recoveryPhrase: string;
  keyring: VaultKeyringWire;
  items: VaultItemWire[];
  manifest: string;
  manifestSig: string;
}

interface UseEncryptionReturn {
  /** True when the vault iframe is loaded AND auth info has been set */
  isReady: boolean;
  /** Set the auth info (suiteUserId) for all subsequent vault requests */
  setAuthInfo: (suiteUserId: string) => void;
  request: (type: string, payload?: unknown) => Promise<unknown>;
  generateKeys: () => Promise<{ publicKey: string; signaturePublicKey: string }>;
  commitStagedVault: () => Promise<{ committed: boolean }>;
  uncommitStagedVault: () => Promise<{ uncommitted: boolean }>;
  signKeyRegistration: (
    version: number,
    createdAtMillis: number
  ) => Promise<{
    encryptionPublicKey: string;
    signaturePublicKey: string;
    version: number;
    createdAtMillis: number;
    keyBindingSignature: string;
  }>;
  respondToKeyChallenge: (challengeId: string, ciphertext: string) => Promise<{ response: string; challengeSignature: string }>;
  hasKeys: () => Promise<{ hasKeys: boolean }>;
  getPublicKey: () => Promise<{ publicKey: string; signaturePublicKey?: string }>;
  /** Build the atomic-bootstrap body (recovery phrase, keyring, sealed items, manifest). */
  prepareOnboarding: (opts?: {
    lang?: 'french' | 'english';
    version?: number;
    generation?: number;
    reusePhrase?: string;
  }) => Promise<OnboardingBundle>;
  /** Re-derive the keyring under a new recovery phrase (VRK unchanged). */
  changeRecoveryPhrase: (lang?: 'french' | 'english') => Promise<{ recoveryPhrase: string; keyring: VaultKeyringWire }>;
  /** Cold-unlock: rebuild the vault from the server copy using the recovery phrase. */
  restoreFromPhrase: (
    recoveryPhrase: string,
    token: string
  ) => Promise<{ publicKey: string; signaturePublicKey: string; isActiveVault: boolean; vaultCreatedAtMillis: number }>;
  /** Bring the dormant vault a phrase unlocks back as the current one (after user confirmation). */
  reactivateVault: (
    recoveryPhrase: string,
    token: string
  ) => Promise<{
    reactivated: boolean;
    publicKey: string;
    signaturePublicKey: string;
    disabledVaultId: string | null;
    disabledVaultCreatedAtMillis: number | null;
  }>;
  /** Run one pull-merge-push sync pass, authenticating with the given token. */
  syncVault: (token: string | null) => Promise<{ status: string; revision: number }>;
  /** New device: mint an ephemeral key, returning its public key + short fingerprint. */
  startDeviceApproval: () => Promise<{ devicePublicKey: string; decimalFingerprint: string }>;
  /** New device: unwrap the forwarded VRK and adopt the vault locally. */
  completeDeviceApproval: (wrappedDeviceBootstrap: string, token: string | null) => Promise<{ adopted: boolean }>;
  /** Enrolled device: verify the fingerprint and wrap the VRK for the new device. */
  approveDevice: (devicePublicKey: string, expectedDecimal: string) => Promise<{ wrappedDeviceBootstrap: string }>;
}

export function useEncryption({ vaultUrl }: UseEncryptionOptions): UseEncryptionReturn {
  const [iframeReady, setIframeReady] = useState(false);
  const [hasAuth, setHasAuth] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const userIdRef = useRef<string | null>(null);
  const pendingRef = useRef<Map<string, { resolve: (value: unknown) => void; reject: (reason: unknown) => void }>>(new Map());

  useEffect(() => {
    // Create hidden vault iframe
    const iframe = document.createElement('iframe');
    iframe.src = `${vaultUrl}/bridge.html`;
    iframe.style.display = 'none';
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    document.body.appendChild(iframe);
    iframeRef.current = iframe;

    const handleMessage = (event: MessageEvent) => {
      if (new URL(vaultUrl).origin !== event.origin) {
        return;
      }

      const data = event.data as VaultResponse;

      if (data.type === MSG_VAULT_READY) {
        setIframeReady(true);

        return;
      }

      if (data.type === MSG_VAULT_RESULT && 'requestId' in data) {
        const pending = pendingRef.current.get(data.requestId);

        if (pending) {
          pendingRef.current.delete(data.requestId);

          if (data.success) {
            pending.resolve(data.data);
          } else {
            // Preserve the marshalled code so callers can branch on it (e.g. a
            // vault-integrity failure vs a wrong recovery phrase), not just the message.
            pending.reject(data.code ? new VaultError(data.code as VaultErrorCode, data.error) : new Error(data.error));
          }
        }
      }
    };

    window.addEventListener('message', handleMessage);

    return () => {
      window.removeEventListener('message', handleMessage);

      // Reject all pending requests on cleanup to avoid dangling promises
      for (const [, pending] of pendingRef.current) {
        pending.reject(new Error('Vault iframe destroyed'));
      }
      pendingRef.current.clear();

      if (iframe.parentNode) {
        iframe.parentNode.removeChild(iframe);
      }
    };
  }, [vaultUrl]);

  const setAuthInfo = useCallback((suiteUserId: string) => {
    userIdRef.current = suiteUserId;
    setHasAuth(true);
  }, []);

  const request = useCallback(
    async (type: string, payload?: unknown): Promise<unknown> => {
      if (!iframeRef.current?.contentWindow) {
        throw new Error('Vault iframe not ready');
      }

      if (!userIdRef.current) {
        throw new Error('Auth info is required. Call setAuthInfo() first.');
      }

      const requestId = crypto.randomUUID();
      const vaultOrigin = new URL(vaultUrl).origin;

      return new Promise((resolve, reject) => {
        // Timeout after 30s (libsodium WASM init + key generation)
        const timeout = setTimeout(() => {
          pendingRef.current.delete(requestId);
          reject(new Error('Vault request timed out'));
        }, 30000);

        pendingRef.current.set(requestId, {
          resolve: (value) => {
            clearTimeout(timeout);
            resolve(value);
          },
          reject: (reason) => {
            clearTimeout(timeout);
            reject(reason);
          },
        });

        iframeRef.current!.contentWindow!.postMessage({ type, requestId, suiteUserId: userIdRef.current, payload }, vaultOrigin);
      });
    },
    [vaultUrl]
  );

  const generateKeys = useCallback(() => request(MSG_VAULT_GENERATE_KEYS) as Promise<{ publicKey: string; signaturePublicKey: string }>, [request]);

  const commitStagedVault = useCallback(() => request(MSG_VAULT_COMMIT_STAGED) as Promise<{ committed: boolean }>, [request]);

  const uncommitStagedVault = useCallback(() => request(MSG_VAULT_UNCOMMIT_STAGED) as Promise<{ uncommitted: boolean }>, [request]);

  const signKeyRegistration = useCallback(
    (version: number, createdAtMillis: number) =>
      request(MSG_VAULT_SIGN_KEY_REGISTRATION, { version, createdAtMillis }) as Promise<{
        encryptionPublicKey: string;
        signaturePublicKey: string;
        version: number;
        createdAtMillis: number;
        keyBindingSignature: string;
      }>,
    [request]
  );

  const respondToKeyChallenge = useCallback(
    (challengeId: string, ciphertext: string) =>
      request(MSG_VAULT_RESPOND_TO_KEY_CHALLENGE, { challengeId, ciphertext }) as Promise<{ response: string; challengeSignature: string }>,
    [request]
  );

  const hasKeys = useCallback(() => request(MSG_VAULT_HAS_KEYS) as Promise<{ hasKeys: boolean }>, [request]);

  const getPublicKey = useCallback(() => request(MSG_VAULT_GET_PUBLIC_KEY) as Promise<{ publicKey: string; signaturePublicKey?: string }>, [request]);

  const prepareOnboarding = useCallback(
    (opts?: { lang?: 'french' | 'english'; version?: number; generation?: number }) =>
      request(MSG_VAULT_PREPARE_ONBOARDING, opts) as Promise<OnboardingBundle>,
    [request]
  );

  const changeRecoveryPhrase = useCallback(
    (lang?: 'french' | 'english') =>
      request(MSG_VAULT_CHANGE_RECOVERY_PHRASE, lang ? { lang } : undefined) as Promise<{ recoveryPhrase: string; keyring: VaultKeyringWire }>,
    [request]
  );

  const restoreFromPhrase = useCallback(
    (recoveryPhrase: string, token: string) =>
      request(MSG_VAULT_RESTORE_FROM_PHRASE, { recoveryPhrase, token }) as Promise<{
        publicKey: string;
        signaturePublicKey: string;
        isActiveVault: boolean;
        vaultCreatedAtMillis: number;
      }>,
    [request]
  );

  const reactivateVault = useCallback(
    (recoveryPhrase: string, token: string) =>
      request(MSG_VAULT_REACTIVATE, { recoveryPhrase, token }) as Promise<{
        reactivated: boolean;
        publicKey: string;
        signaturePublicKey: string;
        disabledVaultId: string | null;
        disabledVaultCreatedAtMillis: number | null;
      }>,
    [request]
  );

  const syncVault = useCallback(
    (token: string | null) => request(MSG_VAULT_SYNC, { token }) as Promise<{ status: string; revision: number }>,
    [request]
  );

  const startDeviceApproval = useCallback(
    () => request(MSG_VAULT_START_DEVICE_APPROVAL) as Promise<{ devicePublicKey: string; decimalFingerprint: string }>,
    [request]
  );

  const completeDeviceApproval = useCallback(
    (wrappedDeviceBootstrap: string, token: string | null) =>
      request(MSG_VAULT_COMPLETE_DEVICE_APPROVAL, { wrappedDeviceBootstrap, token }) as Promise<{ adopted: boolean }>,
    [request]
  );

  const approveDevice = useCallback(
    (devicePublicKey: string, expectedDecimal: string) =>
      request(MSG_VAULT_APPROVE_DEVICE, { devicePublicKey, expectedDecimal }) as Promise<{ wrappedDeviceBootstrap: string }>,
    [request]
  );

  const isReady = iframeReady && hasAuth;

  return {
    isReady,
    setAuthInfo,
    request,
    generateKeys,
    commitStagedVault,
    uncommitStagedVault,
    signKeyRegistration,
    respondToKeyChallenge,
    hasKeys,
    getPublicKey,
    prepareOnboarding,
    changeRecoveryPhrase,
    restoreFromPhrase,
    reactivateVault,
    syncVault,
    startDeviceApproval,
    completeDeviceApproval,
    approveDevice,
  };
}
