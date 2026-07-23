import React, { type ReactNode } from 'react';

import { EncryptionContext, type EncryptionContextType } from '@encryption/src/ui/providers/EncryptionProvider';
import { sampleOnboardingBundle, samplePublicKey, sampleRecoveryPhrase, sampleVaultKeyring } from '@encryption/src/ui/testing/fixtures';

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

export function createMockEncryption(overrides: Partial<EncryptionContextType> = {}): EncryptionContextType {
  return {
    isReady: true,
    setAuthInfo: (suiteUserId: string, internalUserId?: string | null) => {
      console.log('[vault] setAuthInfo', suiteUserId, internalUserId);
    },
    request: stub('request', undefined as unknown),
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
    }),
    syncVault: stub('syncVault', { status: 'ok', revision: 1 }),
    startDeviceApproval: stub('startDeviceApproval', {
      devicePublicKey: samplePublicKey.encryption_public_key,
      decimalFingerprint: '00317 12345 67890 12345 67890 12345 67890 12345',
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
