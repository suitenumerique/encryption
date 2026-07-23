import { type ReactNode, createContext, useContext } from 'react';

import { useEncryption } from '@encryption/src/ui/hooks/useEncryption';

export type EncryptionContextType = ReturnType<typeof useEncryption>;

export const EncryptionContext = createContext<EncryptionContextType | null>(null);

// Read from runtime config (injected by the server) with dev fallback.
const runtimeConfig = (window as unknown as { __ENCRYPTION_CONFIG__?: { vaultUrl?: string } }).__ENCRYPTION_CONFIG__;
const VAULT_URL = runtimeConfig?.vaultUrl ?? 'http://data.encryption.localhost:7200';

interface EncryptionProviderProps {
  children: ReactNode;
}

export function EncryptionProvider({ children }: EncryptionProviderProps) {
  const encryption = useEncryption({ vaultUrl: VAULT_URL });

  return <EncryptionContext.Provider value={encryption}>{children}</EncryptionContext.Provider>;
}

export function useEncryptionContext(): EncryptionContextType {
  const context = useContext(EncryptionContext);

  if (!context) {
    throw new Error('useEncryptionContext must be used within an EncryptionProvider');
  }

  return context;
}
