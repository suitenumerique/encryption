import {
  MSG_INTERFACE_CLOSED,
  MSG_INTERFACE_CONTEXT,
  MSG_INTERFACE_ONBOARDING_COMPLETE,
  MSG_INTERFACE_REQUEST_CONTEXT,
  MSG_INTERFACE_RESIZE,
  MSG_INTERFACE_SET_THEME,
  MSG_INTERFACE_VERIFY_COMPLETE,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_EMERGENCY_PENDING,
  MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITH_KEY,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_READY,
  MSG_VAULT_RESULT,
  MSG_VAULT_REWRAP_NESTED_KEY,
  MSG_VAULT_SHARE_KEYS,
  MSG_VAULT_WRAP_NESTED_KEY,
} from '@encryption/src/shared/constants';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import { type RecipientLabel, interfaceContextSchema } from '@encryption/src/shared/schemas/interface-context';
import type { VaultResponse } from '@encryption/src/shared/schemas/post-message';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

export type { RecipientLabel } from '@encryption/src/shared/schemas/interface-context';

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
  /**
   * The identity provider's `sub` claim for the logged-in user. Products only
   * ever deal in subs — their own APIs know users by sub, and every SDK
   * operation (recipients, fingerprints, profiles) takes subs. The vault
   * resolves them to its internal, migration-stable user ids at its boundary
   * (local alias map, then public registry); that internal id never has to be
   * handled, stored, or even seen by a product.
   */
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
// The vault's emergency-pending push is a bare routing signal: which prompt the
// interface should lead with, nothing identifying. The product forwards it
// verbatim; the interface renders the actual list from its own JWT fetch.
interface EmergencyPendingContext {
  recovery: boolean;
  invitation: boolean;
}

// How long the SDK-owned emergency overlay waits for the interface to prove it
// booted before removing itself (see surfaceEmergencyPending). Generous enough
// for a cold bundle on a slow connection, short enough that a broken interface
// does not hold the product page hostage.
const EMERGENCY_OVERLAY_BOOT_TIMEOUT_MS = 15_000;

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
  // "Verify recipients" trust modal: the SDK-created full-screen overlay hosting
  // the interface iframe and the resolver awaiting its outcome.
  private verifyOverlay: HTMLElement | null = null;
  private verifyResolve: ((outcome: 'resolved' | 'cancelled') => void) | null = null;
  // SDK-owned overlay for the auto-surfaced emergency-access prompt, plus a
  // once-per-page-load latch (it reappears on the next load while actionable,
  // without nagging within a session).
  private emergencyOverlay: HTMLDivElement | null = null;
  private emergencySurfaced = false;
  private emergencyWatchdog: ReturnType<typeof setTimeout> | null = null;
  // The per-flow context owed to the interface iframe, set when a flow opens and
  // cleared on teardown / closeInterface. Ephemeral by design: recipient labels
  // (name/email) are display-only and never persisted, synced, or sent to any
  // server; only the flow currently open carries a block here.
  private pendingContext: {
    verifyRecipients?: { recipients: Record<string, RecipientLabel> };
    recipientProfile?: { userId: string; label: RecipientLabel };
    emergencyPending?: EmergencyPendingContext;
  } | null = null;

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
   * Update the Cunningham theme. If the interface iframe is open, sends it a
   * theme message so it re-themes in place.
   * @param theme - Cunningham theme name: "default", "dark", "dsfr", "dsfr-dark", "anct", "anct-dark", etc.
   */
  setTheme(theme: string): void {
    this.theme = theme;

    // Drive the theme purely via postMessage. Reassigning interfaceIframe.src
    // would force a full navigation back to the iframe's original route,
    // discarding any in-app state (e.g. an unsaved recovery phrase mid-backup)
    // if the interface has since navigated internally.
    if (this.interfaceIframe?.contentWindow) {
      this.interfaceIframe.contentWindow.postMessage({ type: MSG_INTERFACE_SET_THEME, theme }, this.interfaceOrigin);
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
    this.sendContext(this.interfaceIframe?.contentWindow);
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
      this.initTimeoutId = setTimeout(() => reject(new VaultError(VaultErrorCode.TIMEOUT, 'Vault initialization timed out')), this.timeout);
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

    // Resolve any in-flight verify overlay as cancelled before tearing it down,
    // so a pending share awaiting its outcome rejects (original error) instead of
    // hanging.
    this.completeVerify('cancelled');

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
   * encrypts `data` with it, and wraps the new key once per recipient.
   *
   * Pass recipients as a labeled map (OIDC sub → {email, name?}), not public
   * keys — the subs your product already holds for its users. The vault
   * resolves + trust-checks each recipient (binding + TOFU 'trusted' with
   * matching fingerprint, keyed internally so trust survives an OIDC provider
   * migration) before wrapping, and throws UNTRUSTED_RECIPIENT if any is
   * unverified or untrusted. Call checkFingerprints first to resolve any
   * 'unknown' contacts. The labels are display-only and used only if the trust
   * modal opens; the vault request itself sees just the subs.
   *
   * Use this for standalone encrypted files (no parent) and for the root
   * folder of an encrypted subtree.
   *
   * @returns encryptedContent and encryptedKeys (userId → wrappedKey)
   */
  async encryptWithoutKey(
    data: ArrayBuffer,
    recipients: Record<string, RecipientLabel>,
    options?: { optimizeMemory?: boolean }
  ): Promise<{ encryptedContent: ArrayBuffer; encryptedKeys: Record<string, ArrayBuffer> }> {
    return this.withRecipientVerification(recipients, (isFinalAttempt) =>
      this.encryptWithoutKeyRequest(data, Object.keys(recipients), options, isFinalAttempt)
    );
  }

  private async encryptWithoutKeyRequest(
    data: ArrayBuffer,
    recipientSubs: string[],
    options: { optimizeMemory?: boolean } | undefined,
    allowTransfer: boolean
  ): Promise<{ encryptedContent: ArrayBuffer; encryptedKeys: Record<string, ArrayBuffer> }> {
    const optimize = options?.optimizeMemory === true;
    // Transferring `data` detaches it, so only do it on the FINAL attempt: an
    // auto-verify retry needs the buffer intact if the first attempt is refused
    // for an untrusted recipient. (optimizeMemory is a client-side hint here; the
    // vault op does not read it.)
    const transferables = optimize && allowTransfer ? [data] : undefined;
    return (await this.vaultRequest(MSG_VAULT_ENCRYPT_WITHOUT_KEY, { data, recipientSubs, optimizeMemory: optimize }, transferables)) as {
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

    return (await this.vaultRequest(MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY, payload, optimize ? [data] : undefined)) as {
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

    return (await this.vaultRequest(MSG_VAULT_ENCRYPT_WITH_KEY, payload, optimize ? [data] : undefined)) as {
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

    return (await this.vaultRequest(MSG_VAULT_DECRYPT_WITH_KEY, payload, optimize ? [encryptedData] : undefined)) as { data: ArrayBuffer };
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
   *
   * Pass recipients as a labeled map (OIDC sub → {email, name?}), not public
   * keys: the vault resolves each recipient's encryption key from the directory
   * itself and wraps ONLY for identities whose binding verifies AND that you have marked
   * 'trusted' (TOFU) with a matching fingerprint. If any recipient is unverified
   * or untrusted it throws UNTRUSTED_RECIPIENT and wraps for none — call
   * checkFingerprints (and resolve any 'unknown') first. Recipients are resolved
   * in one batched request. The labels are display-only and used only if the
   * trust modal opens; the vault request itself sees just the userIds.
   *
   * @param encryptedSymmetricKey - current user's encrypted copy of the key
   * @param recipients - map of userId → display label to share with
   * @param encryptedKeyChain - optional chain of wrapped keys for Drive's key hierarchy.
   *   When provided, resolves the chain from entry point to the target item's key
   *   before re-encrypting for the target users.
   * @returns encryptedKeys - Record of userId → ArrayBuffer encrypted symmetric key for each user
   */
  async shareKeys(
    encryptedSymmetricKey: ArrayBuffer,
    recipients: Record<string, RecipientLabel>,
    encryptedKeyChain?: ArrayBuffer[]
  ): Promise<{ encryptedKeys: Record<string, ArrayBuffer> }> {
    return this.withRecipientVerification(recipients, () => this.shareKeysRequest(encryptedSymmetricKey, Object.keys(recipients), encryptedKeyChain));
  }

  private async shareKeysRequest(
    encryptedSymmetricKey: ArrayBuffer,
    recipientSubs: string[],
    encryptedKeyChain?: ArrayBuffer[]
  ): Promise<{ encryptedKeys: Record<string, ArrayBuffer> }> {
    const payload: Record<string, unknown> = { encryptedSymmetricKey, recipientSubs };

    if (encryptedKeyChain) {
      payload.encryptedKeyChain = encryptedKeyChain;
    }

    return (await this.vaultRequest(MSG_VAULT_SHARE_KEYS, payload)) as {
      encryptedKeys: Record<string, ArrayBuffer>;
    };
  }

  /**
   * Fetch registered users for a list of OIDC subs (the ids your product
   * already holds). The vault calls the encryption server itself (products
   * never touch it) and verifies each record's binding signature before
   * returning. The map is keyed by the subs you queried; subs with no active
   * registration are absent (that person never onboarded encryption). Use it
   * when building a sharing UI: it tells you who has keys, their fingerprint,
   * and whether the directory record is coherent (`verified`).
   */
  async fetchPublicKeys(subs: string[]): Promise<Record<string, RegisteredUser>> {
    const { users } = (await this.vaultRequest(MSG_VAULT_FETCH_PUBLIC_KEYS, { subs })) as {
      users: Record<string, RegisteredUser>;
    };

    return users;
  }

  // =========================================================================
  // Fingerprint registry (TOFU pattern)
  // =========================================================================

  /**
   * Check fingerprints provided by the product against the vault's local registry.
   * The product sends the fingerprints it stored at share time, keyed by OIDC
   * sub; results echo the same subs back (the vault translates to its internal
   * trust keys on its side).
   *
   * Returns results with status: "trusted", "refused", or "unknown" (needs user decision).
   */
  async checkFingerprints(userFingerprints: Record<string, string>): Promise<{
    results: Array<{
      userId: string;
      knownFingerprint: string | null;
      providedFingerprint: string;
      // 'mismatch' = a recorded fingerprint that has since changed (transient, not
      // a persisted status); 'unknown' = seen but not yet verified.
      status: 'trusted' | 'refused' | 'unknown' | 'mismatch';
    }>;
  }> {
    return (await this.vaultRequest(MSG_VAULT_CHECK_FINGERPRINTS, { userFingerprints })) as {
      results: Array<{
        userId: string;
        knownFingerprint: string | null;
        providedFingerprint: string;
        status: 'trusted' | 'refused' | 'unknown' | 'mismatch';
      }>;
    };
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
   * Compute a 128-bit DECIMAL fingerprint of a public key: the first 16 bytes of
   * its SHA-256, read big-endian as a fixed-width 40-digit decimal. Matches the
   * device-pairing fingerprint so every surface shows the same value.
   * This is a pure client-side operation — no vault iframe needed.
   *
   * @param publicKey - The public key as ArrayBuffer (from fetchPublicKeys or getPublicKey)
   */
  async computeKeyFingerprint(publicKey: ArrayBuffer): Promise<string> {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey)).slice(0, 16);

    let n = 0n;
    for (const b of hash) n = (n << 8n) | BigInt(b);

    return n.toString().padStart(40, '0');
  }

  /**
   * Format a raw decimal fingerprint for display, grouped in blocks of five.
   */
  formatFingerprint(fingerprint: string): string {
    return formatDecimalFingerprint(fingerprint);
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
   * Open the encryption settings (view fingerprint, delete keys).
   */
  openSettings(container: HTMLElement): void {
    this.openInterface(container, '/settings');
  }

  /**
   * Open device approval: enroll this device from another, or approve a new one.
   */
  openDeviceApproval(container: HTMLElement): void {
    this.openInterface(container, '/device-approval');
  }

  /**
   * Open the emergency-access (trusted contacts) management screen: designate
   * contacts, accept a designation, follow or refuse a running recovery.
   */
  openEmergencyAccess(container: HTMLElement): void {
    this.openInterface(container, '/emergency-access');
  }

  /**
   * Open the per-recipient profile: the recipient's current trust decision, their
   * identity fingerprint (for out-of-band comparison), and Trust / Refuse actions.
   * Opened explicitly by the product (e.g. clicking a person in its share UI), so
   * it mounts in a product-provided container like the other open* methods.
   * `userId` is the recipient's OIDC sub, like every id a product passes.
   */
  openRecipientProfile(container: HTMLElement, userId: string, label: RecipientLabel): void {
    // Reset per-flow state, then set the profile target so the context handshake
    // carries it (and its display label) once the iframe loads / requests context.
    this.openInterface(container, '/recipient-profile');
    this.pendingContext = { recipientProfile: { userId, label } };
    this.sendContext(this.interfaceIframe?.contentWindow);
  }

  /**
   * Close the interface iframe if it is open.
   */
  closeInterface(): void {
    if (this.interfaceIframe) {
      this.removeIframe(this.interfaceIframe);
      this.interfaceIframe = null;
    }

    // Context scoped to a single interface flow — clear it so a later open()
    // of another screen never re-sends a stale flow block.
    this.pendingContext = null;
    this.teardownEmergencyOverlay();
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

    this.interfaceIframe = this.buildInterfaceIframe(path);
    this.interfaceIframe.style.minHeight = '300px';
    container.appendChild(this.interfaceIframe);
  }

  /**
   * Construct and configure an interface iframe for `path` (sandbox, allow,
   * theme/lang hash, context handshake). Mounting is left to the caller so the
   * same setup serves both the product-provided container (openInterface) and
   * the SDK-created full-screen overlay (openVerifyRecipients).
   *
   * `overlay` travels in the HASH, not in the postMessage context, precisely
   * because the context arrives asynchronously: a screen that renders as a page
   * when embedded and as a modal when overlaid would otherwise paint the page
   * variant first (full-width and opaque, over the product) and swap to the modal
   * only once the handshake lands, which reads as a flash.
   */
  private buildInterfaceIframe(path: string, options: { overlay?: boolean } = {}): HTMLIFrameElement {
    const iframe = document.createElement('iframe');
    const hashParams = new URLSearchParams({ theme: this.theme });

    if (this.lang) {
      hashParams.set('lang', this.lang);
    }

    if (options.overlay) {
      hashParams.set('overlay', '1');
    }

    iframe.src = `${this.interfaceUrl}${path}#${hashParams.toString()}`;
    iframe.style.width = '100%';
    iframe.style.border = 'none';
    iframe.style.overflow = 'hidden';
    // Sandbox permissions (principle of least privilege):
    // - allow-scripts: required for the React app and OIDC client
    // - allow-same-origin: required for sessionStorage (OIDC state)
    // - allow-forms: required for potential native form submissions (Cunningham components)
    // - allow-downloads: required for the recovery phrase file download during backup
    // - allow-popups: required for window.open() to open the OIDC login tab
    // - allow-modals: required for window.print() of the recovery kit and the
    //   beforeunload guard that warns before losing an un-saved recovery phrase
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-downloads allow-popups allow-modals');
    // Permissions policy:
    // - camera: required for QR code scanning during device transfer import
    // - clipboard-write: required for the "Copy to clipboard" button during backup
    iframe.setAttribute('allow', 'camera; clipboard-write');
    iframe.setAttribute('title', 'Encryption Interface');

    iframe.addEventListener('load', () => {
      // Send auth context to the interface once it loads.
      // The interface also requests context via a handshake (MSG_INTERFACE_REQUEST_CONTEXT)
      // to handle the race condition where the React app mounts after the load event.
      this.sendContext(iframe.contentWindow);
    });

    return iframe;
  }

  /** The context message currently owed to the interface, or null before auth. */
  private sendContext(target: Window | null | undefined): void {
    if (!target || !this.authContext) {
      return;
    }

    // suiteUserId is always present; the per-flow block (verify / profile), if
    // any, rides on the same channel the interface handshakes for. Validate
    // before posting so a malformed context fails loudly in dev.
    const context = interfaceContextSchema.parse({
      suiteUserId: this.authContext.suiteUserId,
      ...(this.pendingContext ?? {}),
    });

    target.postMessage({ type: MSG_INTERFACE_CONTEXT, ...context }, this.interfaceOrigin);
  }

  /**
   * Open the SDK-owned "verify recipients" overlay on top of the product's own
   * share dialog, and resolve with the user's outcome. The SDK deliberately does
   * NOT draw any chrome here: the container is a minimal, transparent, full-
   * viewport layer, and the interface (a Cunningham Modal) draws the whole modal
   * (its own backdrop + card) inside the transparent iframe, so it matches the
   * rest of the interface UI. Tears the overlay down once the outcome is in.
   */
  private openVerifyRecipients(recipients: Record<string, RecipientLabel>): Promise<'resolved' | 'cancelled'> {
    this.closeInterface();
    this.teardownVerifyOverlay();

    this.pendingContext = { verifyRecipients: { recipients } };

    // Minimal full-viewport layer: no background, no card. The React app inside
    // draws the modal; keeping this transparent lets its backdrop show through.
    const overlay = document.createElement('div');
    overlay.style.cssText = ['position: fixed', 'inset: 0', 'z-index: 2147483647'].join(';');

    const iframe = this.buildInterfaceIframe('/verify-recipients', { overlay: true });
    // Fill the layer and stay transparent so the interface-drawn backdrop is what
    // the user sees (not an SDK-managed card).
    iframe.style.height = '100%';
    iframe.style.background = 'transparent';
    iframe.setAttribute('allowtransparency', 'true');
    // Assigning to interfaceIframe lets the shared context handshake and theme
    // updates target this iframe exactly like any other flow.
    this.interfaceIframe = iframe;
    overlay.appendChild(iframe);
    document.body.appendChild(overlay);
    this.verifyOverlay = overlay;

    return new Promise<'resolved' | 'cancelled'>((resolve) => {
      this.verifyResolve = resolve;
    });
  }

  /**
   * Auto-open the interface over the product when the vault reports actionable
   * emergency-access state: a running recovery request against the user's vault
   * (which they must be able to refuse without hunting for a menu) or a pending
   * trusted-contact designation to accept. Same transparent-overlay technique
   * as the verify-recipients flow; at most once per page load, and never while
   * another interface flow is already open (the settings screen shows the same
   * state anyway).
   *
   * This one is the ONLY flow the SDK opens on its own initiative, so it is held
   * to a stricter rule than the flows a product asked for: it stays invisible
   * until the interface says it is up, and if it never says so it is removed
   * rather than left covering the page. Both halves hang off the same signal:
   *
   *  - the interface asks for its context (MSG_INTERFACE_REQUEST_CONTEXT) as soon
   *    as its React app mounts, so that is "the remote page is ready";
   *  - until then `visibility: hidden` keeps the blank document, then the app's
   *    first frames, off the screen;
   *  - if it never arrives (bundle blocked, offline, a redirect leaving an empty
   *    document, a crash before mount) the watchdog removes the whole overlay, so
   *    a broken interface never sits on top of the product swallowing clicks. The
   *    user loses nothing: the same state is in the settings screen, and the
   *    load-bearing channel for all of this is email.
   */
  private surfaceEmergencyPending(state: EmergencyPendingContext): void {
    if (this.emergencySurfaced || this.interfaceIframe) return;
    this.emergencySurfaced = true;

    this.pendingContext = {
      emergencyPending: { recovery: state.recovery, invitation: state.invitation },
    };

    const overlay = document.createElement('div');
    // `visibility: hidden` is load-bearing here, and it is the only one of the
    // three obvious ways to hide this that does the right thing:
    //  - `display: none` would stop the iframe laying out, so the app inside can
    //    mount at zero height and measure itself wrong;
    //  - `opacity: 0` would keep the layer in the hit-test, so this full-viewport
    //    element would silently swallow every click on the product underneath;
    //  - `visibility: hidden` still loads and sizes the iframe, but drops the
    //    element from hit-testing entirely, so clicks pass through to the product
    //    until the overlay is revealed. Verified in Chromium.
    overlay.style.cssText = ['position: fixed', 'inset: 0', 'z-index: 2147483647', 'visibility: hidden'].join(';');

    const iframe = this.buildInterfaceIframe('/emergency-access', { overlay: true });
    iframe.style.height = '100%';
    iframe.style.background = 'transparent';
    iframe.setAttribute('allowtransparency', 'true');
    this.interfaceIframe = iframe;
    overlay.appendChild(iframe);
    document.body.appendChild(overlay);
    this.emergencyOverlay = overlay;

    this.emergencyWatchdog = setTimeout(() => {
      this.emergencyWatchdog = null;
      if (this.emergencyOverlay) this.closeInterface();
    }, EMERGENCY_OVERLAY_BOOT_TIMEOUT_MS);
  }

  /**
   * The interface app mounted. Reveal the overlay we kept hidden and stand the
   * watchdog down. No-op for every other flow (the product owns their container).
   */
  private revealEmergencyOverlay(): void {
    if (this.emergencyWatchdog !== null) {
      clearTimeout(this.emergencyWatchdog);
      this.emergencyWatchdog = null;
    }

    if (this.emergencyOverlay) this.emergencyOverlay.style.visibility = 'visible';
  }

  private teardownEmergencyOverlay(): void {
    if (this.emergencyWatchdog !== null) {
      clearTimeout(this.emergencyWatchdog);
      this.emergencyWatchdog = null;
    }

    if (this.emergencyOverlay?.parentNode) {
      this.emergencyOverlay.parentNode.removeChild(this.emergencyOverlay);
    }

    this.emergencyOverlay = null;
  }

  private completeVerify(outcome: 'resolved' | 'cancelled'): void {
    const resolve = this.verifyResolve;
    this.verifyResolve = null;
    this.teardownVerifyOverlay();
    resolve?.(outcome);
  }

  private teardownVerifyOverlay(): void {
    if (this.verifyOverlay?.parentNode) {
      this.verifyOverlay.parentNode.removeChild(this.verifyOverlay);
    }

    this.verifyOverlay = null;
    this.pendingContext = null;
    // The overlay owned the interface iframe, so it is gone with it.
    this.interfaceIframe = null;
  }

  /**
   * Run a recipient-bearing operation, and on UNTRUSTED_RECIPIENT open the shared
   * verify modal for the ORIGINAL recipients (full labeled map; the interface
   * surfaces only the blocked ones). If the user trusts them all, retry the
   * operation exactly once; otherwise rethrow the original error so the product
   * sees the share failed (all-or-nothing). Any other error rethrows unchanged.
   * This is always on: whether to prompt for trust is not a product choice, so
   * there is no opt-out.
   */
  private async withRecipientVerification<T>(recipients: Record<string, RecipientLabel>, run: (isFinalAttempt: boolean) => Promise<T>): Promise<T> {
    try {
      // The first attempt may fail the trust gate and be retried, so it must not
      // transfer (detach) any buffers; the retry is the final attempt.
      return await run(false);
    } catch (err) {
      if (err instanceof VaultError && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
        const outcome = await this.openVerifyRecipients(recipients);

        if (outcome === 'resolved') {
          // The user trusted every recipient (accept-fingerprint ran in the
          // vault), so the local registry changed: notify listeners and retry
          // the operation exactly once.
          this.emit('fingerprint-changed', undefined as never);

          return await run(true);
        }
      }

      throw err;
    }
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

    if ((data as { type?: string }).type === MSG_VAULT_EMERGENCY_PENDING) {
      const payload = (data as unknown as { payload?: EmergencyPendingContext }).payload;

      if (payload) this.surfaceEmergencyPending(payload);

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

    const msg = data as { type: string; publicKey?: string; height?: number; outcome?: 'resolved' | 'cancelled' };

    switch (msg.type) {
      case MSG_INTERFACE_REQUEST_CONTEXT:
        // Handshake: interface iframe requests its context on mount. That request
        // is also the proof the remote page came up, which is what the SDK-owned
        // emergency overlay waits for before showing itself.
        this.sendContext(this.interfaceIframe?.contentWindow);
        this.revealEmergencyOverlay();
        break;
      case MSG_INTERFACE_RESIZE:
        // Auto-resize: the interface iframe communicates its content height.
        // `Math.ceil` alone is sufficient to avoid subpixel scrollbars; an
        // additional buffer compounded with the child's ResizeObserver
        // into a feedback loop that grew the iframe ~2px per interaction.
        // Skipped for the verify overlay: it is a full-viewport iframe drawing
        // its own modal, so collapsing it to content height would break the
        // backdrop.
        if (msg.height && this.interfaceIframe && !this.verifyOverlay) {
          this.interfaceIframe.style.height = `${Math.ceil(msg.height)}px`;
        }
        break;
      case MSG_INTERFACE_ONBOARDING_COMPLETE:
        this.emit('onboarding:complete', { publicKey: msg.publicKey ?? '' });
        break;
      case MSG_INTERFACE_VERIFY_COMPLETE:
        // The verify overlay reports its outcome; any value other than an explicit
        // 'resolved' aborts the share (all-or-nothing).
        this.completeVerify(msg.outcome === 'resolved' ? 'resolved' : 'cancelled');
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
