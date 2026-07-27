import React, { type ReactNode } from 'react';

import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_SIGN_REQUEST,
} from '@encryption/src/shared/constants';
import { EncryptionContext, type EncryptionContextType } from '@encryption/src/ui/providers/EncryptionProvider';
import {
  sampleEmergencyDesignateBody,
  sampleFingerprint,
  sampleOnboardingBundle,
  samplePublicKey,
  sampleRecoveryPhrase,
  sampleVaultKeyring,
} from '@encryption/src/ui/testing/fixtures';

/**
 * Stub vault for stories. The real EncryptionProvider mounts a cross-origin
 * iframe and talks to it over postMessage, which cannot exist in Storybook: MSW
 * intercepts HTTP, not postMessage. So stories get a resolved-value stub of the
 * same context instead, and override only the calls their scenario exercises.
 *
 * Every operation logs, so a story that walks a flow shows which vault calls it
 * made in the Actions panel.
 */
function stub<T>(name: string, value: T): (...args: unknown[]) => Promise<T> {
  return async (...args: unknown[]) => {
    console.log(`[vault] ${name}`, ...args);

    return value;
  };
}

/**
 * Recipient lookups do NOT go through the HTTP API: the vault resolves subs and
 * owns the TOFU registry, so components ask it over postMessage. The stub has to
 * answer those messages with real shapes, otherwise a component destructuring
 * `{ users }` throws before it can render anything.
 *
 * A story overrides `request` in `parameters.encryption` to drive a scenario
 * (unknown vs trusted recipient, an unregistered sub, a rejection).
 */
const vaultRequest = async (type: string, payload?: unknown): Promise<unknown> => {
  console.log('[vault] request', type, payload);

  switch (type) {
    case MSG_VAULT_FETCH_PUBLIC_KEYS: {
      // Callers pass `subs` (recipient subs) OR `userIds` (internal ids); answer both.
      const p = payload as { subs?: string[]; userIds?: string[] } | undefined;
      const ids = p?.subs ?? p?.userIds ?? [];

      return {
        users: Object.fromEntries(ids.map((id) => [id, { userId: samplePublicKey.user_id, identityFingerprint: sampleFingerprint, verified: true }])),
      };
    }
    case MSG_VAULT_CHECK_FINGERPRINTS: {
      // Every recipient comes back 'unknown', the honest default: a first
      // encounter is never trusted on sight.
      const userFingerprints = (payload as { userFingerprints?: Record<string, string> } | undefined)?.userFingerprints ?? {};

      return {
        results: Object.entries(userFingerprints).map(([userId, providedFingerprint]) => ({ userId, providedFingerprint, status: 'unknown' })),
      };
    }
    case MSG_VAULT_GET_KNOWN_FINGERPRINTS:
      // Nothing known yet: a first encounter is 'unknown', never trust-on-first-use.
      return { fingerprints: {} };
    case MSG_VAULT_ACCEPT_FINGERPRINT:
    case MSG_VAULT_REFUSE_FINGERPRINT:
      return {};
    case MSG_VAULT_SIGN_REQUEST:
      return { signature: samplePublicKey.key_binding_signature };
    default:
      return undefined;
  }
};

export function createMockEncryption(overrides: Partial<EncryptionContextType> = {}): EncryptionContextType {
  return {
    isReady: true,
    setAuthInfo: (suiteUserId: string, internalUserId?: string | null) => {
      console.log('[vault] setAuthInfo', suiteUserId, internalUserId);
    },
    request: vaultRequest,
    resolveInternalUser: stub('resolveInternalUser', samplePublicKey.user_id),
    generateKeys: stub('generateKeys', {
      publicKey: samplePublicKey.encryption_public_key,
      signaturePublicKey: samplePublicKey.signature_public_key,
    }),
    commitStagedVault: stub('commitStagedVault', { committed: true }),
    uncommitStagedVault: stub('uncommitStagedVault', { uncommitted: true }),
    signKeyRegistration: stub('signKeyRegistration', {
      encryptionPublicKey: samplePublicKey.encryption_public_key,
      signaturePublicKey: samplePublicKey.signature_public_key,
      version: samplePublicKey.version,
      createdAtMillis: samplePublicKey.created_at_millis,
      keyBindingSignature: samplePublicKey.key_binding_signature,
    }),
    respondToKeyChallenge: stub('respondToKeyChallenge', {
      response: samplePublicKey.key_binding_signature,
      challengeSignature: samplePublicKey.key_binding_signature,
    }),
    hasKeys: stub('hasKeys', { hasKeys: true }),
    getPublicKey: stub('getPublicKey', {
      publicKey: samplePublicKey.encryption_public_key,
      signaturePublicKey: samplePublicKey.signature_public_key,
    }),
    prepareOnboarding: stub('prepareOnboarding', sampleOnboardingBundle),
    changeRecoveryPhrase: stub('changeRecoveryPhrase', { recoveryPhrase: sampleRecoveryPhrase, keyring: sampleVaultKeyring }),
    restoreFromPhrase: stub('restoreFromPhrase', {
      publicKey: samplePublicKey.encryption_public_key,
      signaturePublicKey: samplePublicKey.signature_public_key,
      isActiveVault: true,
      vaultCreatedAtMillis: samplePublicKey.created_at_millis,
    }),
    reactivateVault: stub('reactivateVault', {
      reactivated: true,
      publicKey: samplePublicKey.encryption_public_key,
      signaturePublicKey: samplePublicKey.signature_public_key,
      disabledVaultId: null,
      disabledVaultCreatedAtMillis: null,
      emergencyUnlock: false,
    }),
    createEmergencyEscrow: stub('createEmergencyEscrow', sampleEmergencyDesignateBody),
    buildEmergencyRearms: stub('buildEmergencyRearms', { rearms: [] }),
    verifyEscrows: async (contacts: Array<{ id: string }>) => ({ results: contacts.map((c) => ({ id: c.id, status: 'ok' as const })) }),
    revealEmergencyPhrase: stub('revealEmergencyPhrase', { recoveryPhrase: sampleRecoveryPhrase }),
    syncVault: stub('syncVault', { status: 'ok', revision: 1 }),
    startDeviceApproval: stub('startDeviceApproval', {
      devicePublicKey: samplePublicKey.encryption_public_key,
      decimalFingerprint: sampleFingerprint,
    }),
    completeDeviceApproval: stub('completeDeviceApproval', { adopted: true }),
    approveDevice: stub('approveDevice', { wrappedDeviceBootstrap: samplePublicKey.key_binding_signature }),
    ...overrides,
  } as EncryptionContextType;
}

interface MockEncryptionProviderProps {
  children: ReactNode;
  value?: Partial<EncryptionContextType>;
}

export function MockEncryptionProvider({ children, value }: MockEncryptionProviderProps) {
  return <EncryptionContext.Provider value={createMockEncryption(value)}>{children}</EncryptionContext.Provider>;
}
