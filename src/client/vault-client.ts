import {
  MSG_INTERFACE_CLOSED,
  MSG_INTERFACE_CONTEXT,
  MSG_INTERFACE_ONBOARDING_COMPLETE,
  MSG_INTERFACE_REQUEST_CONTEXT,
  MSG_INTERFACE_RESIZE,
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITH_KEY,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_READY,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_RESULT,
  MSG_VAULT_REWRAP_NESTED_KEY,
  MSG_VAULT_SHARE_KEYS,
  MSG_VAULT_WRAP_NESTED_KEY,
} from '@encryption/src/shared/constants';
import type { VaultResponse } from '@encryption/src/shared/schemas/post-message';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

export interface EncryptionClientOptions {
  /** URL of the vault domain (data.encryption), e.g. "https://data.encryption.numerique.gouv.fr" */
  vaultUrl: string;
  /** URL of the interface domain (encryption), e.g. "https://encryption.numerique.gouv.fr" */
  interfaceUrl: string;
  /** Timeout in ms for vault operations (default: 30000) */
  timeout?: number;
  /**
   * Cunningham theme name for the interface iframe.
   * Standard names: "default", "dark", "dsfr", "dsfr-dark", "anct", "anct-dark".
   * Default: "default"
   */
  theme?: string;
  /** Language code for the interface iframe: "fr", "en", etc. (default: browser language) */
  lang?: string;
}

export interface AuthContext {
  /** Authenticated user ID (cross-product suite identifier from the identity provider's sub claim) */
  suiteUserId: string;
}

/**
 * Union on `verified` on purpose: `encryptionPublicKey` is a usable
 * `ArrayBuffer` only in the verified branch (`null` otherwise), so a caller
 * cannot wrap a key for a forged / incoherent directory entry without the
 * compiler stopping them. Identity and encryption key live in one per-user
 * entry so the two can never disagree for a user.
 */
export type RegisteredUser =
  | {
      verified: true;
      signaturePublicKey: ArrayBuffer;
      identityFingerprint: string;
      version: number;
      createdAtMillis: number;
      encryptionPublicKey: ArrayBuffer;
    }
  | {
      verified: false;
      signaturePublicKey: ArrayBuffer;
      identityFingerprint: string;
      version: number;
      createdAtMillis: number;
      encryptionPublicKey: null;
    };

export interface EncryptionClientEventMap {
  /** Fired when the hidden vault iframe is ready for encrypt/decrypt operations */
  [MSG_VAULT_READY]: void;
  /** Fired when the user completes onboarding (key generation + backup) */
  'onboarding:complete': { publicKey: string };
  /** Fired when the user cancels or closes the interface */
  [MSG_INTERFACE_CLOSED]: void;
  /** Fired on errors from the vault or the interface */
  error: Error;
  /** Fired when keys changed from another tab/product (via BroadcastChannel) */
  'keys-changed': void;
  /** Fired when keys were destroyed from another tab/product (via BroadcastChannel) */
  'keys-destroyed': void;
  /** Fired when a fingerprint is accepted or refused in the local registry */
  'fingerprint-changed': void;
}

type Listener<K extends keyof EncryptionClientEventMap> = (data: EncryptionClientEventMap[K]) => void;

/**
 * Client SDK for integrating encryption into suite products.
 *
 * Orchestrates two iframes:
 * - data.encryption (hidden): encrypt, decrypt, check keys
 * - encryption (visible): onboarding, backup, restore, settings
 *
 * Products load this script from encryption:
 *
 *   <script src="https://encryption.numerique.gouv.fr/client.js"></script>
 *   <script>
 *     const encryption = new EncryptionClient.VaultClient({
 *       vaultUrl: 'https://data.encryption.numerique.gouv.fr',
 *       interfaceUrl: 'https://encryption.numerique.gouv.fr',
 *     });
 *
 *     await encryption.init();
 *
 *     if (!(await encryption.hasKeys()).hasKeys) {
 *       // Opens visible interface iframe for onboarding
 *       encryption.openOnboarding(document.getElementById('modal-container'));
 *       encryption.on('onboarding:complete', ({ publicKey }) => { ... });
 *     }
 *
 *     const { encryptedContent, encryptedKeys } = await encryption.encryptWithoutKey(data, userPublicKeys);
 *   </script>
 */
export class VaultClient {
  private vaultIframe: HTMLIFrameElement | null = null;
  private interfaceIframe: HTMLIFrameElement | null = null;
  private pending = new Map<string, { resolve: (value: unknown) => void; reject: (reason: unknown) => void }>();
  private listeners = new Map<string, Set<Listener<keyof EncryptionClientEventMap>>>();
  private vaultReadyResolve: (() => void) | null = null;
  private initTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private messageHandler: ((event: MessageEvent) => void) | null = null;
  private vaultUrl: string;
  private interfaceUrl: string;
  private vaultOrigin: string;
  private interfaceOrigin: string;
  private timeout: number;
  private theme: string;
  private lang: string | null;
  private authContext: AuthContext | null = null;

  constructor(options: EncryptionClientOptions) {
    this.vaultUrl = options.vaultUrl;
    this.interfaceUrl = options.interfaceUrl;
    this.vaultOrigin = new URL(options.vaultUrl).origin;
    this.interfaceOrigin = new URL(options.interfaceUrl).origin;
    this.timeout = options.timeout ?? 30000;
    this.theme = options.theme ?? 'default';
    this.lang = options.lang ?? null;
  }

  /**
   * Update the Cunningham theme. If the interface iframe is open, updates the hash to trigger a theme change.
   * @param theme - Cunningham theme name: "default", "dark", "dsfr", "dsfr-dark", "anct", "anct-dark", etc.
   */
  setTheme(theme: string): void {
    this.theme = theme;

    // If the interface iframe is open, update its hash so it picks up the theme change
    if (this.interfaceIframe) {
      const currentSrc = new URL(this.interfaceIframe.src);
      currentSrc.hash = `theme=${theme}`;
      this.interfaceIframe.src = currentSrc.toString();
    }
  }

  /**
   * Set the authentication context. Must be called before opening the interface.
   * The suiteUserId is passed to the interface iframe so it can register
   * public keys on the server and perform device transfers.
   */
  setAuthContext(context: AuthContext): void {
    this.authContext = context;

    // If the interface iframe is already open, update it immediately
    // (e.g., after a token refresh)
    if (this.interfaceIframe?.contentWindow) {
      this.interfaceIframe.contentWindow.postMessage(
        {
          type: MSG_INTERFACE_CONTEXT,
          suiteUserId: context.suiteUserId,
        },
        this.interfaceOrigin
      );
    }
  }

  /**
   * Read back the auth context that was set via {@link setAuthContext}.
   * Returns `null` until `setAuthContext` has been called. Useful when
   * the host app needs to identify the currently-bound suite user from
   * code that doesn't otherwise have access to the auth state — e.g.
   * the Drive driver's encryption-aware move handler, which has to
   * verify the operator (mover) keeps a per-user wrap during a
   * re-anchor and would otherwise need to thread the user identifier
   * through every call site.
   */
  getAuthContext(): AuthContext | null {
    return this.authContext;
  }

  // =========================================================================
  // Lifecycle
  // =========================================================================

  /**
   * Initialize the encryption client.
   * Creates a hidden vault iframe (data.encryption) and waits for it to be ready.
   */
  async init(): Promise<void> {
    if (this.vaultIframe) {
      // Programmer-error path — init() called twice. Keeping it as a
      // plain Error since no consumer should branch on it.
      throw new Error('EncryptionClient already initialized');
    }

    const vaultReady = new Promise<void>((resolve) => {
      this.vaultReadyResolve = resolve;
    });

    this.messageHandler = this.handleMessage.bind(this);
    window.addEventListener('message', this.messageHandler);

    // Create hidden vault iframe
    this.vaultIframe = document.createElement('iframe');
    this.vaultIframe.src = `${this.vaultUrl}/bridge.html`;
    this.vaultIframe.style.display = 'none';
    // Minimal sandbox — the vault only runs crypto scripts and accesses IndexedDB.
    // - allow-scripts: required for libsodium WASM, postMessage handling, Service Worker
    // - allow-same-origin: required for IndexedDB access (key storage) and fetch API
    this.vaultIframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    this.vaultIframe.setAttribute('title', 'Encryption Vault');
    document.body.appendChild(this.vaultIframe);

    const timeoutPromise = new Promise<void>((_, reject) => {
      this.initTimeoutId = setTimeout(
        () => reject(new VaultError(VaultErrorCode.TIMEOUT, 'Vault initialization timed out')),
        this.timeout,
      );
    });

    try {
      await Promise.race([vaultReady, timeoutPromise]);
    } finally {
      if (this.initTimeoutId !== null) {
        clearTimeout(this.initTimeoutId);
        this.initTimeoutId = null;
      }
    }
  }

  /**
   * Clean up all iframes and event listeners.
   */
  destroy(): void {
    if (this.initTimeoutId !== null) {
      clearTimeout(this.initTimeoutId);
      this.initTimeoutId = null;
    }

    if (this.messageHandler) {
      window.removeEventListener('message', this.messageHandler);
      this.messageHandler = null;
    }

    this.removeIframe(this.vaultIframe);
    this.removeIframe(this.interfaceIframe);
    this.vaultIframe = null;
    this.interfaceIframe = null;
    this.pending.clear();
    this.listeners.clear();
  }

  // =========================================================================
  // Data operations (via data.encryption hidden iframe)
  // =========================================================================

  /** Check if the user has encryption keys on this device. */
  async hasKeys(): Promise<{ hasKeys: boolean }> {
    return (await this.vaultRequest(MSG_VAULT_HAS_KEYS)) as { hasKeys: boolean };
  }

  /** Get the user's public key as ArrayBuffer. */
  async getPublicKey(): Promise<{ publicKey: ArrayBuffer }> {
    return (await this.vaultRequest(MSG_VAULT_GET_PUBLIC_KEY)) as { publicKey: ArrayBuffer };
  }

  /**
   * Create a new ROOT encrypted resource. Mints a fresh symmetric key,
   * encrypts `data` with it, and wraps the new key once per user under
   * that user's public key.
   *
   * Use this for standalone encrypted files (no parent) and for the root
   * folder of an encrypted subtree.
   *
   * @returns encryptedContent and encryptedKeys (userId → wrappedKey)
   */
  async encryptWithoutKey(
    data: ArrayBuffer,
    userPublicKeys: Record<string, ArrayBuffer>,
    options?: { optimizeMemory?: boolean }
  ): Promise<{ encryptedContent: ArrayBuffer; encryptedKeys: Record<string, ArrayBuffer> }> {
    const optimize = options?.optimizeMemory === true;
    return (await this.vaultRequest(
      MSG_VAULT_ENCRYPT_WITHOUT_KEY,
      { data, userPublicKeys, optimizeMemory: optimize },
      optimize ? [data] : undefined,
    )) as {
      encryptedContent: ArrayBuffer;
      encryptedKeys: Record<string, ArrayBuffer>;
    };
  }

  /**
   * Create a new NESTED encrypted resource inside an existing encrypted
   * subtree. Resolves `entry + chain` to the parent folder's key, mints a
   * fresh symmetric key, encrypts `data` with it, and wraps the new key
   * under the parent's key.
   *
   * Use this for creating a file inside an already-encrypted folder.
   * Persist the returned `wrappedKey` on the new item's DB row.
   *
   * @param data - ArrayBuffer content to encrypt
   * @param encryptedSymmetricKey - caller's entry key (asymmetric bootstrap
   *   into the subtree, same value used for decryptWithKey)
   * @param encryptedKeyChain - optional symmetric wrappings from entry down
   *   to the parent folder (exclusive of the new resource, since it doesn't
   *   exist yet). Empty/omitted means the entry key IS the parent's key.
   */
  async encryptNestedWithoutKey(
    data: ArrayBuffer,
    encryptedSymmetricKey: ArrayBuffer,
    encryptedKeyChain?: ArrayBuffer[],
    options?: { optimizeMemory?: boolean }
  ): Promise<{ encryptedContent: ArrayBuffer; wrappedKey: ArrayBuffer }> {
    const optimize = options?.optimizeMemory === true;
    const payload: Record<string, unknown> = {
      data,
      encryptedSymmetricKey,
      optimizeMemory: optimize,
    };

    if (encryptedKeyChain) {
      payload.encryptedKeyChain = encryptedKeyChain;
    }

    return (await this.vaultRequest(
      MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
      payload,
      optimize ? [data] : undefined,
    )) as {
      encryptedContent: ArrayBuffer;
      wrappedKey: ArrayBuffer;
    };
  }

  /**
   * Encrypt content with an EXISTING symmetric key — pure symmetric mirror
   * of `decryptWithKey`. No new key is minted.
   *
   * Without `encryptedKeyChain`: resolves `encryptedSymmetricKey` (user's
   * entry key) and encrypts with it. Used by the flat model (Docs).
   *
   * With `encryptedKeyChain`: resolves entry + chain to the terminal
   * symmetric key and encrypts with it. Used by the collaborative relay
   * to encrypt messages tied to an existing file inside an encrypted
   * hierarchy, so that sender and receiver converge on the same K_file.
   */
  async encryptWithKey(
    data: ArrayBuffer,
    encryptedSymmetricKey: ArrayBuffer,
    encryptedKeyChain?: ArrayBuffer[],
    options?: { optimizeMemory?: boolean }
  ): Promise<{ encryptedData: ArrayBuffer }> {
    const optimize = options?.optimizeMemory === true;
    const payload: Record<string, unknown> = {
      data,
      encryptedSymmetricKey,
      optimizeMemory: optimize,
    };

    if (encryptedKeyChain) {
      payload.encryptedKeyChain = encryptedKeyChain;
    }

    return (await this.vaultRequest(
      MSG_VAULT_ENCRYPT_WITH_KEY,
      payload,
      optimize ? [data] : undefined,
    )) as {
      encryptedData: ArrayBuffer;
    };
  }

  /**
   * Decrypt content using a separately provided encrypted symmetric key.
   * The symmetric key decryption is cached per session for performance.
   *
   * @param encryptedData - ArrayBuffer ciphertext to decrypt
   * @param encryptedSymmetricKey - user's encrypted copy of the symmetric key
   * @param encryptedKeyChain - optional chain of wrapped keys for Drive's key hierarchy.
   *   When provided, resolves the chain from entry point to target before decrypting.
   */
  async decryptWithKey(
    encryptedData: ArrayBuffer,
    encryptedSymmetricKey: ArrayBuffer,
    encryptedKeyChain?: ArrayBuffer[],
    options?: { optimizeMemory?: boolean }
  ): Promise<{ data: ArrayBuffer }> {
    const optimize = options?.optimizeMemory === true;
    const payload: Record<string, unknown> = {
      encryptedData,
      encryptedSymmetricKey,
      optimizeMemory: optimize,
    };

    if (encryptedKeyChain) {
      payload.encryptedKeyChain = encryptedKeyChain;
    }

    return (await this.vaultRequest(
      MSG_VAULT_DECRYPT_WITH_KEY,
      payload,
      optimize ? [encryptedData] : undefined,
    )) as { data: ArrayBuffer };
  }

  /**
   * Re-wrap a nested resource's symmetric key from one parent chain onto
   * another. Used when MOVING an encrypted file/folder between positions
   * inside the same encrypted subtree: the file's content is left
   * untouched (still encrypted with K_file), but K_file's wrapping
   * follows its new parent.
   *
   * @param encryptedSymmetricKey - the user's entry-point key (root key
   *   wrapped under the user's pubkey). Same value for both old and new
   *   chains since this operation stays within a single encrypted root.
   * @param oldEncryptedKey - the resource's K_file as currently stored,
   *   wrapped under its OLD parent's key.
   * @param oldEncryptedKeyChain - chain of wrapped folder keys from the
   *   entry point down to (and including) the OLD parent's key. Omit /
   *   pass `undefined` when the OLD parent IS the encryption root.
   * @param newEncryptedKeyChain - chain entry → NEW parent. Omit when
   *   the NEW parent is the encryption root.
   * @returns the resource's K_file re-wrapped under the NEW parent's
   *   key — caller persists this on the resource's DB row, replacing
   *   the old wrapping.
   */
  async rewrapNestedKey(
    encryptedSymmetricKey: ArrayBuffer,
    oldEncryptedKey: ArrayBuffer,
    oldEncryptedKeyChain?: ArrayBuffer[],
    newEncryptedKeyChain?: ArrayBuffer[]
  ): Promise<{ newEncryptedKey: ArrayBuffer }> {
    const payload: Record<string, unknown> = {
      encryptedSymmetricKey,
      oldEncryptedKey,
    };

    if (oldEncryptedKeyChain) {
      payload.oldEncryptedKeyChain = oldEncryptedKeyChain;
    }

    if (newEncryptedKeyChain) {
      payload.newEncryptedKeyChain = newEncryptedKeyChain;
    }

    return (await this.vaultRequest(MSG_VAULT_REWRAP_NESTED_KEY, payload)) as {
      newEncryptedKey: ArrayBuffer;
    };
  }

  /**
   * Wrap an existing per-user-anchored symmetric key under a parent
   * chain. Symmetric reverse of {@link shareKeys} (which goes 1→N
   * chain→per-user); this goes 1→1 per-user→chain.
   *
   * Used when MOVING a self-rooted encrypted resource (per-user
   * wraps on its access rows) INTO an encrypted subtree: K_item is
   * recovered from the user's per-user wrap, then wrapped under the
   * destination parent's chain so the resource stops being a root
   * and joins the destination tree.
   *
   * @param userEncryptedKey - the resource's per-user wrap from the
   *   caller's access row (`encrypted_item_symmetric_key_for_user`).
   * @param newEntryEncryptedSymmetricKey - user's entry-point key
   *   for the destination tree (the tree's root key wrapped under
   *   their pubkey — same value `getKeyChain` returns as
   *   `encrypted_key_for_user` for any item under that tree).
   * @param newEncryptedKeyChain - chain entry → NEW parent. Omit
   *   when the new parent IS the destination tree's root.
   * @returns the resource's K_item wrapped under the new parent's
   *   key — caller persists this on the resource's row.
   */
  async wrapNestedKey(
    userEncryptedKey: ArrayBuffer,
    newEntryEncryptedSymmetricKey: ArrayBuffer,
    newEncryptedKeyChain?: ArrayBuffer[]
  ): Promise<{ newEncryptedKey: ArrayBuffer }> {
    const payload: Record<string, unknown> = {
      userEncryptedKey,
      newEntryEncryptedSymmetricKey,
    };
    if (newEncryptedKeyChain) {
      payload.newEncryptedKeyChain = newEncryptedKeyChain;
    }
    return (await this.vaultRequest(MSG_VAULT_WRAP_NESTED_KEY, payload)) as {
      newEncryptedKey: ArrayBuffer;
    };
  }

  /**
   * Share an existing document's or item's symmetric key with additional users.
   * Accepts the same map format as encryptWithoutKey.
   *
   * @param encryptedSymmetricKey - current user's encrypted copy of the key
   * @param userPublicKeys - Record of userId → ArrayBuffer public key for each new user
   * @param encryptedKeyChain - optional chain of wrapped keys for Drive's key hierarchy.
   *   When provided, resolves the chain from entry point to the target item's key
   *   before re-encrypting for the target users.
   * @returns encryptedKeys - Record of userId → ArrayBuffer encrypted symmetric key for each user
   */
  async shareKeys(
    encryptedSymmetricKey: ArrayBuffer,
    userPublicKeys: Record<string, ArrayBuffer>,
    encryptedKeyChain?: ArrayBuffer[]
  ): Promise<{ encryptedKeys: Record<string, ArrayBuffer> }> {
    const payload: Record<string, unknown> = { encryptedSymmetricKey, userPublicKeys };

    if (encryptedKeyChain) {
      payload.encryptedKeyChain = encryptedKeyChain;
    }

    return (await this.vaultRequest(MSG_VAULT_SHARE_KEYS, payload)) as {
      encryptedKeys: Record<string, ArrayBuffer>;
    };
  }

  /**
   * Fetch registered users for a list of user IDs. The vault calls the
   * encryption server itself (products never touch it) and verifies each
   * record's binding signature before returning. Users with no active
   * registration are absent from the map.
   */
  async fetchPublicKeys(userIds: string[]): Promise<Record<string, RegisteredUser>> {
    const { users } = (await this.vaultRequest(MSG_VAULT_FETCH_PUBLIC_KEYS, { userIds })) as {
      users: Record<string, RegisteredUser>;
    };

    return users;
  }

  // =========================================================================
  // Fingerprint registry (TOFU pattern)
  // =========================================================================

  /**
   * Check fingerprints provided by the product against the vault's local registry.
   * The product sends the fingerprints it stored at share time.
   *
   * Returns results with status: "trusted", "refused", or "unknown" (needs user decision).
   */
  async checkFingerprints(
    userFingerprints: Record<string, string>,
    currentUserId?: string
  ): Promise<{
    results: Array<{
      userId: string;
      knownFingerprint: string | null;
      providedFingerprint: string;
      status: 'trusted' | 'refused' | 'unknown';
    }>;
  }> {
    return (await this.vaultRequest(MSG_VAULT_CHECK_FINGERPRINTS, { userFingerprints, currentUserId })) as {
      results: Array<{
        userId: string;
        knownFingerprint: string | null;
        providedFingerprint: string;
        status: 'trusted' | 'refused' | 'unknown';
      }>;
    };
  }

  /**
   * Accept a fingerprint: mark as trusted in the local registry.
   */
  async acceptFingerprint(userId: string, fingerprint: string): Promise<void> {
    await this.vaultRequest(MSG_VAULT_ACCEPT_FINGERPRINT, { userId, fingerprint });
    this.emit('fingerprint-changed', undefined as never);
  }

  /**
   * Refuse a fingerprint: mark as refused in the local registry (shown in red in the UI).
   */
  async refuseFingerprint(userId: string, fingerprint: string): Promise<void> {
    await this.vaultRequest(MSG_VAULT_REFUSE_FINGERPRINT, { userId, fingerprint });
    this.emit('fingerprint-changed', undefined as never);
  }

  /**
   * Get all known fingerprints with their status from the local registry.
   */
  async getKnownFingerprints(): Promise<{
    fingerprints: Record<string, { fingerprint: string; status: 'trusted' | 'refused' | 'unknown' }>;
  }> {
    return (await this.vaultRequest(MSG_VAULT_GET_KNOWN_FINGERPRINTS)) as {
      fingerprints: Record<string, { fingerprint: string; status: 'trusted' | 'refused' | 'unknown' }>;
    };
  }

  // =========================================================================
  // Key fingerprints (client-side, no iframe round-trip)
  // =========================================================================

  /**
   * Compute a SHA-256 fingerprint of a public key.
   * Returns 16 lowercase hex characters for storage (e.g. "a1b2c3d4e5f67890").
   * This is a pure client-side operation — no vault iframe needed.
   *
   * @param publicKey - The public key as ArrayBuffer (from fetchPublicKeys or getPublicKey)
   */
  async computeKeyFingerprint(publicKey: ArrayBuffer): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', publicKey);

    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 16);
  }

  /**
   * Format a raw fingerprint for display: "a1b2c3d4e5f67890" → "A1B2 C3D4 E5F6 7890"
   */
  formatFingerprint(fingerprint: string): string {
    return fingerprint
      .replace(/(.{4})/g, '$1 ')
      .trim()
      .toUpperCase();
  }

  // =========================================================================
  // Interface operations (via encryption visible iframe)
  // =========================================================================

  /**
   * Open the encryption interface for onboarding (key generation + backup).
   * The product provides a container element where the interface iframe will be mounted.
   * The product is responsible for showing/hiding this container (e.g. in a modal).
   *
   * Listen to 'onboarding:complete' and 'interface:closed' events for results.
   */
  openOnboarding(container: HTMLElement): void {
    this.openInterface(container, '/onboarding');
  }

  /**
   * Open the encryption interface for key backup/export.
   */
  openBackup(container: HTMLElement): void {
    this.openInterface(container, '/backup');
  }

  /**
   * Open the encryption interface for key restoration from backup.
   */
  openRestore(container: HTMLElement): void {
    this.openInterface(container, '/restore');
  }

  /**
   * Open the encryption interface for device transfer.
   */
  openDeviceTransfer(container: HTMLElement): void {
    this.openInterface(container, '/device-transfer');
  }

  /**
   * Open the encryption settings (view fingerprint, delete keys).
   */
  openSettings(container: HTMLElement): void {
    this.openInterface(container, '/settings');
  }

  /**
   * Close the interface iframe if it is open.
   */
  closeInterface(): void {
    if (this.interfaceIframe) {
      this.removeIframe(this.interfaceIframe);
      this.interfaceIframe = null;
    }
  }

  // =========================================================================
  // Events
  // =========================================================================

  on<K extends keyof EncryptionClientEventMap>(event: K, listener: Listener<K>): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }

    this.listeners.get(event)!.add(listener as Listener<keyof EncryptionClientEventMap>);
  }

  off<K extends keyof EncryptionClientEventMap>(event: K, listener: Listener<K>): void {
    this.listeners.get(event)?.delete(listener as Listener<keyof EncryptionClientEventMap>);
  }

  // =========================================================================
  // Private
  // =========================================================================

  private openInterface(container: HTMLElement, path: string): void {
    this.closeInterface();

    this.interfaceIframe = document.createElement('iframe');
    const hashParams = new URLSearchParams({ theme: this.theme });

    if (this.lang) {
      hashParams.set('lang', this.lang);
    }

    this.interfaceIframe.src = `${this.interfaceUrl}${path}#${hashParams.toString()}`;
    this.interfaceIframe.style.width = '100%';
    this.interfaceIframe.style.minHeight = '300px';
    this.interfaceIframe.style.border = 'none';
    this.interfaceIframe.style.overflow = 'hidden';
    // Sandbox permissions (principle of least privilege):
    // - allow-scripts: required for the React app and OIDC client
    // - allow-same-origin: required for sessionStorage (OIDC state)
    // - allow-forms: required for potential native form submissions (Cunningham components)
    // - allow-downloads: required for the recovery phrase file download during backup
    // - allow-popups: required for window.open() to open the OIDC login tab
    this.interfaceIframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-downloads allow-popups');
    // Permissions policy:
    // - camera: required for QR code scanning during device transfer import
    // - clipboard-write: required for the "Copy to clipboard" button during backup
    this.interfaceIframe.setAttribute('allow', 'camera; clipboard-write');
    this.interfaceIframe.setAttribute('title', 'Encryption Interface');
    container.appendChild(this.interfaceIframe);

    const origin = this.interfaceOrigin;

    this.interfaceIframe.addEventListener('load', () => {
      // Send auth context to the interface once it loads.
      // The interface also requests context via a handshake (MSG_INTERFACE_REQUEST_CONTEXT)
      // to handle the race condition where the React app mounts after the load event.
      if (this.authContext) {
        this.interfaceIframe?.contentWindow?.postMessage(
          {
            type: MSG_INTERFACE_CONTEXT,
            suiteUserId: this.authContext.suiteUserId,
          },
          origin
        );
      }
    });
  }

  private async vaultRequest(type: string, payload?: Record<string, unknown>, transferables?: Transferable[]): Promise<unknown> {
    if (!this.vaultIframe?.contentWindow) {
      throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'Vault not initialized. Call init() first.');
    }

    if (!this.authContext?.suiteUserId) {
      throw new VaultError(VaultErrorCode.AUTH_REQUIRED, 'Auth context with suiteUserId is required. Call setAuthContext() first.');
    }

    const requestId = crypto.randomUUID();
    const { suiteUserId } = this.authContext;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new VaultError(VaultErrorCode.TIMEOUT, `Vault request "${type}" timed out after ${this.timeout}ms`));
      }, this.timeout);

      this.pending.set(requestId, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (reason) => {
          clearTimeout(timer);
          reject(reason);
        },
      });

      const message = { type, requestId, suiteUserId, ...(payload ? { payload } : {}) };

      if (transferables && transferables.length > 0) {
        this.vaultIframe!.contentWindow!.postMessage(message, this.vaultOrigin, transferables);
      } else {
        this.vaultIframe!.contentWindow!.postMessage(message, this.vaultOrigin);
      }
    });
  }

  private handleMessage(event: MessageEvent): void {
    // Messages from the vault (data.encryption)
    if (event.origin === this.vaultOrigin) {
      const msg = event.data as { type?: string };

      // Forwarded BroadcastChannel notifications from the vault iframe
      if (msg?.type === 'vault:keys-changed') {
        this.emit('keys-changed', undefined as never);

        return;
      }

      if (msg?.type === 'vault:keys-destroyed') {
        this.emit('keys-destroyed', undefined as never);

        return;
      }

      this.handleVaultMessage(event.data as VaultResponse);

      return;
    }

    // Messages from the interface (.encryption)
    if (event.origin === this.interfaceOrigin) {
      this.handleInterfaceMessage(event.data);

      return;
    }
  }

  private handleVaultMessage(data: VaultResponse): void {
    if (!data || typeof data !== 'object' || !('type' in data)) {
      return;
    }

    if (data.type === MSG_VAULT_READY) {
      this.vaultReadyResolve?.();
      this.emit(MSG_VAULT_READY, undefined as never);

      return;
    }

    if (data.type === MSG_VAULT_RESULT && 'requestId' in data) {
      const pending = this.pending.get(data.requestId);

      if (pending) {
        this.pending.delete(data.requestId);

        if (data.success) {
          pending.resolve(data.data);
        } else {
          // Reconstruct as a VaultError when the vault marshalled a
          // code; falls back to UNKNOWN if the response came from an
          // older vault build that didn't include one yet.
          const code = (data as { code?: string }).code as VaultErrorCode | undefined;
          const error = new VaultError(code ?? VaultErrorCode.UNKNOWN, data.error);
          pending.reject(error);
          this.emit('error', error);
        }
      }
    }
  }

  private handleInterfaceMessage(data: unknown): void {
    if (!data || typeof data !== 'object' || !('type' in (data as Record<string, unknown>))) {
      return;
    }

    const msg = data as { type: string; publicKey?: string; height?: number };

    switch (msg.type) {
      case MSG_INTERFACE_REQUEST_CONTEXT:
        // Handshake: interface iframe requests its context on mount
        if (this.interfaceIframe?.contentWindow) {
          if (this.authContext) {
            this.interfaceIframe.contentWindow.postMessage(
              {
                type: MSG_INTERFACE_CONTEXT,
                suiteUserId: this.authContext.suiteUserId,
              },
              this.interfaceOrigin
            );
          }
        }
        break;
      case MSG_INTERFACE_RESIZE:
        // Auto-resize: the interface iframe communicates its content height.
        // `Math.ceil` alone is sufficient to avoid subpixel scrollbars; an
        // additional buffer compounded with the child's ResizeObserver
        // into a feedback loop that grew the iframe ~2px per interaction.
        if (msg.height && this.interfaceIframe) {
          this.interfaceIframe.style.height = `${Math.ceil(msg.height)}px`;
        }
        break;
      case MSG_INTERFACE_ONBOARDING_COMPLETE:
        this.emit('onboarding:complete', { publicKey: msg.publicKey ?? '' });
        break;
      case MSG_INTERFACE_CLOSED:
        this.closeInterface();
        this.emit(MSG_INTERFACE_CLOSED, undefined as never);
        break;
    }
  }

  private removeIframe(iframe: HTMLIFrameElement | null): void {
    if (iframe?.parentNode) {
      iframe.parentNode.removeChild(iframe);
    }
  }

  private emit<K extends keyof EncryptionClientEventMap>(event: K, data: EncryptionClientEventMap[K]): void {
    this.listeners.get(event)?.forEach((listener) => (listener as Listener<K>)(data));
  }
}
