/**
 * Encryption Client SDK — Type declarations
 *
 * All cryptographic material (public keys, symmetric keys, content) is
 * transferred as ArrayBuffer. No base64 encoding at the vault boundary.
 * Base64 conversion for server APIs is handled internally by the vault.
 */

/**
 * Stable error codes carried by {@link VaultError}. Match on these in
 * preference to message text — strings can change, codes are part of the
 * SDK contract.
 */
export declare const VaultErrorCode: {
  readonly MISSING_KEYS: 'MISSING_KEYS';
  readonly WRONG_SECRET_KEY: 'WRONG_SECRET_KEY';
  readonly INVALID_BACKUP: 'INVALID_BACKUP';
  readonly INVALID_MNEMONIC: 'INVALID_MNEMONIC';
  readonly NOT_INITIALIZED: 'NOT_INITIALIZED';
  readonly AUTH_REQUIRED: 'AUTH_REQUIRED';
  readonly PRIVILEGED_ORIGIN_REQUIRED: 'PRIVILEGED_ORIGIN_REQUIRED';
  readonly TIMEOUT: 'TIMEOUT';
  readonly IFRAME_REQUIRED: 'IFRAME_REQUIRED';
  readonly CIPHERTEXT_TOO_SHORT: 'CIPHERTEXT_TOO_SHORT';
  readonly UNKNOWN: 'UNKNOWN';
};
export type VaultErrorCode = (typeof VaultErrorCode)[keyof typeof VaultErrorCode];

export declare class VaultError extends Error {
  readonly code: VaultErrorCode;
  constructor(code: VaultErrorCode, message: string);
}

export declare function isVaultError(err: unknown): err is VaultError;

export interface EncryptionClientOptions {
  vaultUrl: string;
  interfaceUrl: string;
  timeout?: number;
  theme?: string;
  lang?: string;
}

export interface AuthContext {
  suiteUserId: string;
}

export interface EncryptionClientEventMap {
  'vault:ready': void;
  'onboarding:complete': { publicKey: string };
  'interface:closed': void;
  error: Error;
  'keys-changed': void;
  'keys-destroyed': void;
}

export declare class VaultClient {
  constructor(options: EncryptionClientOptions);

  // Lifecycle
  init(): Promise<void>;
  destroy(): void;
  setTheme(theme: string): void;
  setAuthContext(context: AuthContext): void;
  getAuthContext(): AuthContext | null;

  // Key management
  hasKeys(): Promise<{ hasKeys: boolean }>;
  getPublicKey(): Promise<{ publicKey: ArrayBuffer }>;
  fetchPublicKeys(userIds: string[]): Promise<{ publicKeys: Record<string, ArrayBuffer> }>;

  /**
   * Memory-tuning option for the four data-handling methods below
   * (`encryptWithoutKey`, `encryptNestedWithoutKey`, `encryptWithKey`,
   * `decryptWithKey`). Defaults to `false` — safe behaviour, the SDK
   * structured-clones the input on its way to the vault and the vault
   * structured-clones the result on its way back. Caller's input
   * buffer stays valid; no `.slice(0)` clones needed.
   *
   * Set to `true` ONLY on hot paths where the caller is happy to
   * relinquish ownership of the input buffer (it gets transferred
   * via postMessage and is detached on the caller side after the
   * call returns) and wants the result transferred back without a
   * copy. Saves two large-buffer copies per call. Only applies to
   * the value buffers — keys, chain, userId etc. are never
   * transferred regardless of this flag.
   */
  // New ROOT resource — mint a fresh key and wrap it under each user's pubkey
  encryptWithoutKey(data: ArrayBuffer, userPublicKeys: Record<string, ArrayBuffer>, options?: { optimizeMemory?: boolean }): Promise<{ encryptedContent: ArrayBuffer; encryptedKeys: Record<string, ArrayBuffer> }>;
  // New NESTED resource — mint a fresh key and wrap it under the parent folder resolved from entry + chain
  encryptNestedWithoutKey(data: ArrayBuffer, encryptedSymmetricKey: ArrayBuffer, encryptedKeyChain?: ArrayBuffer[], options?: { optimizeMemory?: boolean }): Promise<{ encryptedContent: ArrayBuffer; wrappedKey: ArrayBuffer }>;
  // Encrypt with an EXISTING symmetric key — pure symmetric mirror of decryptWithKey
  encryptWithKey(data: ArrayBuffer, encryptedSymmetricKey: ArrayBuffer, encryptedKeyChain?: ArrayBuffer[], options?: { optimizeMemory?: boolean }): Promise<{ encryptedData: ArrayBuffer }>;
  decryptWithKey(encryptedData: ArrayBuffer, encryptedSymmetricKey: ArrayBuffer, encryptedKeyChain?: ArrayBuffer[], options?: { optimizeMemory?: boolean }): Promise<{ data: ArrayBuffer }>;
  // Re-wrap an existing nested resource's symmetric key from one parent chain to another (used when moving an encrypted file/folder within an encrypted subtree)
  rewrapNestedKey(encryptedSymmetricKey: ArrayBuffer, oldEncryptedKey: ArrayBuffer, oldEncryptedKeyChain?: ArrayBuffer[], newEncryptedKeyChain?: ArrayBuffer[]): Promise<{ newEncryptedKey: ArrayBuffer }>;
  // Wrap a per-user-anchored symmetric key under a parent chain (symmetric reverse of shareKeys; used when moving a self-rooted encrypted resource INTO an encrypted subtree)
  wrapNestedKey(userEncryptedKey: ArrayBuffer, newEntryEncryptedSymmetricKey: ArrayBuffer, newEncryptedKeyChain?: ArrayBuffer[]): Promise<{ newEncryptedKey: ArrayBuffer }>;
  shareKeys(encryptedSymmetricKey: ArrayBuffer, userPublicKeys: Record<string, ArrayBuffer>, encryptedKeyChain?: ArrayBuffer[]): Promise<{ encryptedKeys: Record<string, ArrayBuffer> }>;

  // Key fingerprints (client-side, no iframe round-trip)
  computeKeyFingerprint(publicKey: ArrayBuffer): Promise<string>;
  formatFingerprint(fingerprint: string): string;

  // Fingerprint registry (TOFU) — strings are fine for fingerprints (display values)
  checkFingerprints(userFingerprints: Record<string, string>, currentUserId?: string): Promise<{ results: Array<{ userId: string; knownFingerprint: string | null; providedFingerprint: string; status: 'trusted' | 'refused' | 'unknown' }> }>;
  acceptFingerprint(userId: string, fingerprint: string): Promise<void>;
  refuseFingerprint(userId: string, fingerprint: string): Promise<void>;
  getKnownFingerprints(): Promise<{ fingerprints: Record<string, { fingerprint: string; status: 'trusted' | 'refused' | 'unknown' }> }>;

  // Interface operations (visible iframe)
  openOnboarding(container: HTMLElement): void;
  openBackup(container: HTMLElement): void;
  openRestore(container: HTMLElement): void;
  openDeviceTransfer(container: HTMLElement): void;
  openSettings(container: HTMLElement): void;
  closeInterface(): void;

  // Events
  on<K extends keyof EncryptionClientEventMap>(event: K, listener: (data: EncryptionClientEventMap[K]) => void): void;
  off<K extends keyof EncryptionClientEventMap>(event: K, listener: (data: EncryptionClientEventMap[K]) => void): void;
}

declare global {
  interface Window {
    EncryptionClient: {
      VaultClient: typeof VaultClient;
      VaultError: typeof VaultError;
      VaultErrorCode: typeof VaultErrorCode;
      isVaultError: typeof isVaultError;
    };
  }
}
