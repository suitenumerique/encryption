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
export const ASYMMETRIC_ALGORITHM = 'xwing';
export const SYMMETRIC_ALGORITHM = 'xchacha20-poly1305';

// IndexedDB constants
export const DB_NAME = 'encryption';
export const DB_VERSION = 1;

// Store for the user's own key pairs (public + private together)
export const STORE_KEY_PAIRS = 'keyPairs';

// Store for other users' public keys (registry of known contacts)
export const STORE_KNOWN_PUBLIC_KEYS = 'knownPublicKeys';

// ============================================================================
// PostMessage type keys — shared between iframes and their parents
// ============================================================================

// --- Vault requests (parent → data.encryption) ---
export const MSG_VAULT_HAS_KEYS = 'vault:has-keys';
export const MSG_VAULT_GET_PUBLIC_KEY = 'vault:get-public-key';
export const MSG_VAULT_ENCRYPT_WITHOUT_KEY = 'vault:encrypt-without-key'; // New root resource: mints symmetric key + encrypts + wraps for each user's pubkey
export const MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY = 'vault:encrypt-nested-without-key'; // New resource inside an existing encrypted subtree: mints symmetric key + encrypts + wraps under the parent resolved from entry + chain
export const MSG_VAULT_ENCRYPT_WITH_KEY = 'vault:encrypt-with-key'; // Re-encrypt content with an EXISTING symmetric key (symmetric mirror of decryptWithKey, no mint)
export const MSG_VAULT_DECRYPT_WITH_KEY = 'vault:decrypt-with-key'; // Decrypt content with existing symmetric key
export const MSG_VAULT_REWRAP_NESTED_KEY = 'vault:rewrap-nested-key'; // Re-wrap an existing symmetric key from one parent chain to another (used when moving an encrypted resource between folders within the same encrypted subtree)
export const MSG_VAULT_WRAP_NESTED_KEY = 'vault:wrap-nested-key'; // Wrap an existing symmetric key (currently held only as a per-user wrap on the user's pubkey) under a parent chain — the symmetric reverse of `shareKeys`. Used when moving a self-rooted encrypted resource INTO an encrypted subtree.
export const MSG_VAULT_SHARE_KEYS = 'vault:share-keys'; // Wrap existing symmetric key for additional users
export const MSG_VAULT_FETCH_PUBLIC_KEYS = 'vault:fetch-public-keys';

// --- Vault privileged requests (encryption → data.encryption) ---
export const MSG_VAULT_GENERATE_KEYS = 'vault:generate-keys';
export const MSG_VAULT_RESPOND_TO_KEY_CHALLENGE = 'vault:respond-to-key-challenge';
export const MSG_VAULT_EXPORT_BACKUP = 'vault:export-private-key-backup';
export const MSG_VAULT_IMPORT_BACKUP = 'vault:import-private-key-backup';
export const MSG_VAULT_DESTROY_KEYS = 'vault:destroy-keys';
export const MSG_VAULT_PREPARE_TRANSFER_EXPORT = 'vault:prepare-transfer-export';
export const MSG_VAULT_CLAIM_TRANSFER_IMPORT = 'vault:claim-transfer-import';
// --- Vault product requests: fingerprint registry ---
export const MSG_VAULT_CHECK_FINGERPRINTS = 'vault:check-fingerprints';
export const MSG_VAULT_ACCEPT_FINGERPRINT = 'vault:accept-fingerprint';
export const MSG_VAULT_REFUSE_FINGERPRINT = 'vault:refuse-fingerprint';
export const MSG_VAULT_GET_KNOWN_FINGERPRINTS = 'vault:get-known-fingerprints';

// --- Vault responses (data.encryption → parent) ---
export const MSG_VAULT_READY = 'vault:ready';
export const MSG_VAULT_RESULT = 'vault:result';

// --- BroadcastChannel for cross-tab notifications ---
export const BROADCAST_CHANNEL_NAME = 'encryption-vault';
export const BROADCAST_KEYS_CHANGED = 'keys-changed';
export const BROADCAST_KEYS_DESTROYED = 'keys-destroyed';

// --- Interface messages (encryption ↔ parent product) ---
export const MSG_INTERFACE_CONTEXT = 'interface:context';
export const MSG_INTERFACE_REQUEST_CONTEXT = 'interface:request-context';
export const MSG_INTERFACE_RESIZE = 'interface:resize';
export const MSG_INTERFACE_ONBOARDING_COMPLETE = 'interface:onboarding-complete';
export const MSG_INTERFACE_CLOSED = 'interface:closed';
export const MSG_INTERFACE_CSS_VARIABLES = 'interface:css-variables';
