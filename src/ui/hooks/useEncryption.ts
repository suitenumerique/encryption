import { useCallback, useEffect, useRef, useState } from 'react';

import type { MnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import {
  MSG_VAULT_APPROVE_DEVICE,
  MSG_VAULT_BUILD_EMERGENCY_REARMS,
  MSG_VAULT_CHANGE_RECOVERY_PHRASE,
  MSG_VAULT_COMMIT_STAGED,
  MSG_VAULT_COMPLETE_DEVICE_APPROVAL,
  MSG_VAULT_CREATE_EMERGENCY_ESCROW,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_PREPARE_ONBOARDING,
  MSG_VAULT_REACTIVATE,
  MSG_VAULT_READY,
  MSG_VAULT_RESOLVE_USER,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESTORE_FROM_PHRASE,
  MSG_VAULT_RESULT,
  MSG_VAULT_REVEAL_EMERGENCY_PHRASE,
  MSG_VAULT_SIGN_KEY_REGISTRATION,
  MSG_VAULT_START_DEVICE_APPROVAL,
  MSG_VAULT_SYNC,
  MSG_VAULT_UNCOMMIT_STAGED,
  MSG_VAULT_VERIFY_ESCROWS,
} from '@encryption/src/shared/constants';
import type { EmergencyDesignateBody, EmergencyRearmEntry, EmergencyTrustedEntry } from '@encryption/src/shared/schemas/emergency-access';
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
  /**
   * Set the auth info for all subsequent vault requests. `internalUserId`
   * (from /api/me) is what the vault actually operates under — the interface
   * is authoritative for it, which also covers first onboarding where the sub
   * resolves to nothing yet. Until it is known, requests carry the sub alone
   * and the vault resolves it through its alias/registry chain.
   */
  setAuthInfo: (suiteUserId: string, internalUserId?: string | null) => void;
  /**
   * Resolve the declared sub to the internal user id through the vault's
   * alias/registry chain: needs NO OIDC session, so an onboarded user gets
   * their id even with an expired token. Returns null for a never-onboarded
   * user (fall back to /api/me). When the envelope already carries the
   * internal id, the call doubles as a seed: the vault adopts it and persists
   * the sub -> id alias, so later visits resolve offline.
   */
  resolveInternalUser: () => Promise<string | null>;
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
  prepareOnboarding: (opts?: { lang?: MnemonicLanguage; version?: number; generation?: number; reusePhrase?: string }) => Promise<OnboardingBundle>;
  /** Re-derive the keyring under a new recovery phrase (VRK unchanged). */
  changeRecoveryPhrase: (lang?: MnemonicLanguage) => Promise<{ recoveryPhrase: string; keyring: VaultKeyringWire }>;
  /** Cold-unlock: rebuild the vault from the server copy using the recovery phrase. `emergencyUnlock` = a trusted contact's escrowed phrase matched, forcing an immediate phrase change. */
  restoreFromPhrase: (
    recoveryPhrase: string,
    token: string
  ) => Promise<{ publicKey: string; signaturePublicKey: string; isActiveVault: boolean; vaultCreatedAtMillis: number; emergencyUnlock: boolean }>;
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
    emergencyUnlock: boolean;
  }>;
  /** Grantor: build a full designation body (fresh emergency phrase, dormant credential, capsule, binding signature). Requires the contact TOFU-trusted. */
  createEmergencyEscrow: (granteeUserId: string, waitTimeDays: number, lang?: MnemonicLanguage) => Promise<EmergencyDesignateBody>;
  /** Grantor, forced rotation: one fresh escrow per granted relationship, to carry on the keyring PUT. */
  buildEmergencyRearms: (
    rearms: Array<{ emergencyAccessId: string; granteeUserId: string; waitTimeDays: number }>,
    lang?: MnemonicLanguage
  ) => Promise<{ rearms: EmergencyRearmEntry[] }>;
  /** Grantor: audit the server-reported escrow list against the local identity + directory. */
  verifyEscrows: (
    contacts: Array<Pick<EmergencyTrustedEntry, 'id' | 'grantee_user_id' | 'wait_time_days' | 'escrow'>>
  ) => Promise<{ results: Array<{ id: string; status: 'ok' | 'tampered' | 'stale-identity' | 'outdated-key' }> }>;
  /** Contact: verify the released escrow against the pinned grantor identity and render the phrase for the handover kit. */
  revealEmergencyPhrase: (input: {
    grantorUserId: string;
    lang: string;
    waitTimeDays: number;
    escrow: EmergencyTrustedEntry['escrow'];
  }) => Promise<{ recoveryPhrase: string }>;
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
  const internalUserIdRef = useRef<string | null>(null);
  const pendingRef = useRef<Map<string, { resolve: (value: unknown) => void; reject: (reason: unknown) => void }>>(new Map());

  // Resolved when the CURRENT iframe has signalled MSG_VAULT_READY. A freshly
  // appended iframe already exposes a `contentWindow`, but it still holds the
  // `about:blank` document, which inherits the PARENT's origin — so posting to
  // it with the vault's targetOrigin is rejected by the browser ("target origin
  // does not match the recipient window's origin"). A new deferred is installed
  // per iframe (mount, dev remount, vaultUrl change) so requests wait for the
  // frame they will actually be delivered to.
  const readyRef = useRef<{ promise: Promise<void>; resolve: () => void } | null>(null);

  useEffect(() => {
    let markReady = (): void => {};
    const readyDeferred = {
      promise: new Promise<void>((resolve) => {
        markReady = resolve;
      }),
      resolve: () => markReady(),
    };

    readyRef.current = readyDeferred;

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
        readyDeferred.resolve();

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

      // The next iframe starts at `about:blank` again, so readiness MUST NOT
      // carry over: leaving it true lets consumers (and `request`) treat the
      // replacement frame as live and post into the wrong origin.
      setIframeReady(false);

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

  const setAuthInfo = useCallback((suiteUserId: string, internalUserId?: string | null) => {
    userIdRef.current = suiteUserId;
    internalUserIdRef.current = internalUserId ?? null;
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

      // Wait for the iframe to have navigated to the vault origin. Looping
      // because a remount mid-wait swaps the deferred: the one we awaited may
      // belong to an iframe that is already gone, so re-check that the deferred
      // we waited on is still the installed one before posting.
      for (let deferred = readyRef.current; deferred; deferred = readyRef.current) {
        await deferred.promise;

        if (readyRef.current === deferred) break;
      }

      if (!iframeRef.current?.contentWindow) {
        throw new Error('Vault iframe not ready');
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

        iframeRef.current!.contentWindow!.postMessage(
          {
            type,
            requestId,
            suiteUserId: userIdRef.current,
            ...(internalUserIdRef.current ? { internalUserId: internalUserIdRef.current } : {}),
            payload,
          },
          vaultOrigin
        );
      });
    },
    [vaultUrl]
  );

  const resolveInternalUser = useCallback(async (): Promise<string | null> => {
    const result = (await request(MSG_VAULT_RESOLVE_USER)) as { internalUserId: string | null };

    return result.internalUserId;
  }, [request]);

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
    (opts?: { lang?: MnemonicLanguage; version?: number; generation?: number }) =>
      request(MSG_VAULT_PREPARE_ONBOARDING, opts) as Promise<OnboardingBundle>,
    [request]
  );

  const changeRecoveryPhrase = useCallback(
    (lang?: MnemonicLanguage) =>
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
        emergencyUnlock: boolean;
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
        emergencyUnlock: boolean;
      }>,
    [request]
  );

  const createEmergencyEscrow = useCallback(
    (granteeUserId: string, waitTimeDays: number, lang?: MnemonicLanguage) =>
      request(MSG_VAULT_CREATE_EMERGENCY_ESCROW, { granteeUserId, waitTimeDays, lang }) as Promise<EmergencyDesignateBody>,
    [request]
  );

  const buildEmergencyRearms = useCallback(
    (rearms: Array<{ emergencyAccessId: string; granteeUserId: string; waitTimeDays: number }>, lang?: MnemonicLanguage) =>
      request(MSG_VAULT_BUILD_EMERGENCY_REARMS, { rearms, lang }) as Promise<{ rearms: EmergencyRearmEntry[] }>,
    [request]
  );

  const verifyEscrows = useCallback(
    (contacts: Array<Pick<EmergencyTrustedEntry, 'id' | 'grantee_user_id' | 'wait_time_days' | 'escrow'>>) =>
      request(MSG_VAULT_VERIFY_ESCROWS, { contacts }) as Promise<{
        results: Array<{ id: string; status: 'ok' | 'tampered' | 'stale-identity' | 'outdated-key' }>;
      }>,
    [request]
  );

  const revealEmergencyPhrase = useCallback(
    (input: { grantorUserId: string; lang: string; waitTimeDays: number; escrow: EmergencyTrustedEntry['escrow'] }) =>
      request(MSG_VAULT_REVEAL_EMERGENCY_PHRASE, input) as Promise<{ recoveryPhrase: string }>,
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
    resolveInternalUser,
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
    createEmergencyEscrow,
    buildEmergencyRearms,
    verifyEscrows,
    revealEmergencyPhrase,
  };
}
