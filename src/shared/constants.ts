// Cryptographic scheme identifiers
//
// Asymmetric: X-Wing hybrid KEM (X25519 + ML-KEM-768),
// IRTF draft-connolly-cfrg-xwing-kem.
// Symmetric: XChaCha20-Poly1305 (quantum-safe with random nonces).
//
// CRYPTO_VERSION is the format byte prefixed to every serialized binary blob
// (public keys, wrapped symmetric keys, encrypted content). Bumping this byte
// will let legacy decoders dispatch on the prefix to keep older blobs readable.
// Backups carry the same number in their JSON `version` field.
export const CRYPTO_VERSION = 0x01;

// Identity-continuity hop cap: a contact that rotated its identity more than this
// many times since we last verified it is not auto-followed (we fall back to a
// fresh out-of-band check). Shared so the server bounds the chain it walks and
// the client rejects any longer chain, keeping both ends in lockstep. Rotation
// is rare, so this is mostly a guard against a hostile registry serving a long
// fabricated chain.
export const MAX_CONTINUITY_HOPS = 5;

// IndexedDB constants
export const DB_NAME = 'encryption';
export const DB_VERSION = 1;

// Store for the synchronized vault's local cache, keyed by the INTERNAL user
// id: the sealed items + manifest + revision, the wrapped VRK, and the
// non-extractable device key that unwraps it. A copied database is inert
// without the live device key.
export const STORE_VAULT_CACHE = 'vaultCache';

// Alias map `sub -> internal user id`, written alongside the vault cache (same
// moments: onboarding, unlock, sync), so a cached vault always resolves
// offline. Plain metadata: both identifiers are non-secret, no trust decision
// ever reads this map (trust lives in the sealed TOFU store), and every server
// call is independently authenticated.
export const STORE_USER_ALIAS = 'userAlias';

// ============================================================================
// PostMessage type keys — shared between iframes and their parents
// ============================================================================

// --- Vault requests (parent → data.encryption) ---
export const MSG_VAULT_HAS_KEYS = 'vault:has-keys';
export const MSG_VAULT_GET_PUBLIC_KEY = 'vault:get-public-key';
export const MSG_VAULT_ENCRYPT_WITHOUT_KEY = 'vault:encrypt-without-key';
export const MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY = 'vault:encrypt-nested-without-key';
export const MSG_VAULT_ENCRYPT_WITH_KEY = 'vault:encrypt-with-key';
export const MSG_VAULT_DECRYPT_WITH_KEY = 'vault:decrypt-with-key';
export const MSG_VAULT_REWRAP_NESTED_KEY = 'vault:rewrap-nested-key';
export const MSG_VAULT_WRAP_NESTED_KEY = 'vault:wrap-nested-key';
export const MSG_VAULT_SHARE_KEYS = 'vault:share-keys';
export const MSG_VAULT_FETCH_PUBLIC_KEYS = 'vault:fetch-public-keys';

// --- Vault privileged requests (encryption → data.encryption) ---
export const MSG_VAULT_RESOLVE_USER = 'vault:resolve-user';
export const MSG_VAULT_GENERATE_KEYS = 'vault:generate-keys';
export const MSG_VAULT_SIGN_KEY_REGISTRATION = 'vault:sign-key-registration';
export const MSG_VAULT_RESPOND_TO_KEY_CHALLENGE = 'vault:respond-to-key-challenge';
export const MSG_VAULT_DESTROY_KEYS = 'vault:destroy-keys';
export const MSG_VAULT_COMMIT_STAGED = 'vault:commit-staged';
export const MSG_VAULT_UNCOMMIT_STAGED = 'vault:uncommit-staged';
export const MSG_VAULT_PREPARE_ONBOARDING = 'vault:prepare-onboarding';
export const MSG_VAULT_CHANGE_RECOVERY_PHRASE = 'vault:change-recovery-phrase';
export const MSG_VAULT_RESTORE_FROM_PHRASE = 'vault:restore-from-phrase';
export const MSG_VAULT_REACTIVATE = 'vault:reactivate';
export const MSG_VAULT_SYNC = 'vault:sync';
export const MSG_VAULT_SIGN_REQUEST = 'vault:sign-request';
// --- Device approval (enrolled device forwards the VRK to a new one) ---
export const MSG_VAULT_START_DEVICE_APPROVAL = 'vault:start-device-approval';
export const MSG_VAULT_COMPLETE_DEVICE_APPROVAL = 'vault:complete-device-approval';
export const MSG_VAULT_APPROVE_DEVICE = 'vault:approve-device';
// --- Emergency access (trusted contacts) ---
export const MSG_VAULT_CREATE_EMERGENCY_ESCROW = 'vault:create-emergency-escrow';
export const MSG_VAULT_BUILD_EMERGENCY_REARMS = 'vault:build-emergency-rearms';
export const MSG_VAULT_VERIFY_ESCROWS = 'vault:verify-escrows';
export const MSG_VAULT_REVEAL_EMERGENCY_PHRASE = 'vault:reveal-emergency-phrase';
// --- Vault product requests: fingerprint registry ---
export const MSG_VAULT_CHECK_FINGERPRINTS = 'vault:check-fingerprints';
export const MSG_VAULT_ACCEPT_FINGERPRINT = 'vault:accept-fingerprint';
export const MSG_VAULT_REFUSE_FINGERPRINT = 'vault:refuse-fingerprint';
export const MSG_VAULT_GET_KNOWN_FINGERPRINTS = 'vault:get-known-fingerprints';

// --- Vault responses (data.encryption → parent) ---
export const MSG_VAULT_READY = 'vault:ready';
export const MSG_VAULT_RESULT = 'vault:result';
export const MSG_VAULT_EMERGENCY_PENDING = 'vault:emergency-pending';

// --- BroadcastChannel for cross-tab notifications ---
export const BROADCAST_CHANNEL_NAME = 'encryption-vault';
export const BROADCAST_KEYS_CHANGED = 'keys-changed';
export const BROADCAST_KEYS_DESTROYED = 'keys-destroyed';

// --- Interface messages (encryption ↔ parent product) ---
export const MSG_INTERFACE_CONTEXT = 'interface:context';
export const MSG_INTERFACE_REQUEST_CONTEXT = 'interface:request-context';
export const MSG_INTERFACE_RESIZE = 'interface:resize';
export const MSG_INTERFACE_SET_THEME = 'interface:set-theme';
export const MSG_INTERFACE_ONBOARDING_COMPLETE = 'interface:onboarding-complete';
export const MSG_INTERFACE_CLOSED = 'interface:closed';
export const MSG_INTERFACE_VERIFY_COMPLETE = 'interface:verify-complete';
