/**
 * Every domain-separation label, in one place so they can be reviewed together.
 *
 * A key used for one purpose must never produce a value (signature, MAC, hash,
 * ciphertext) that is also valid for another purpose. Each signed message, keyed
 * derivation, fingerprint and AEAD ciphertext therefore binds one of these labels:
 * signed messages and derivations start with it, AEAD ciphertexts carry it as
 * associated data. All follow `lasuite-encryption/<purpose>/v<n>`; the version is
 * bumped when the encoding of what follows changes, never reused.
 *
 * The one exception is the request proof, a JWS whose protected header names its
 * own type (`typ: vault-req+jws`, RFC 8725 explicit typing) and whose signing
 * input starts with `eyJ`, which no label below can.
 *
 * Changing a label invalidates every value made under it.
 */

// Signatures by the identity key (Ed25519).
export const DOMAIN_KEY_REGISTRATION = 'lasuite-encryption/key-registration/v1';
export const DOMAIN_KEY_POP = 'lasuite-encryption/key-pop/v1';
export const DOMAIN_IDENTITY_CONTINUITY = 'lasuite-encryption/identity-continuity/v1';
export const DOMAIN_EMERGENCY_ESCROW = 'lasuite-encryption/emergency-escrow/v1';
export const DOMAIN_VAULT_MANIFEST = 'lasuite-encryption/vault-manifest/v1';
export const DOMAIN_VAULT_AUTH_BINDING = 'lasuite-encryption/vault-auth-binding/v1';

// Signature by the phrase-derived vault auth key.
export const DOMAIN_VAULT_AUTH_CHALLENGE = 'lasuite-encryption/vault-auth-challenge/v1';

// Derivations from the recovery phrase: the Argon2id salt, then the two subkeys
// of the KEK, so the KEK itself never keys two primitives.
export const DOMAIN_VAULT_KDF_SALT = 'lasuite-encryption/vault-kdf-salt/v1';
export const DOMAIN_VAULT_AUTH_SEED = 'lasuite-encryption/vault-auth-seed/v1';
export const DOMAIN_VRK_WRAP_KEY = 'lasuite-encryption/vrk-wrap-key/v1';

// Derivations from an X-Wing shared secret, so the KEM output itself never keys
// two primitives: the key that seals a wrapped key, and the registration
// challenge's HMAC key.
export const DOMAIN_KEM_WRAP_KEY = 'lasuite-encryption/kem-wrap-key/v1';
export const DOMAIN_KEY_POSSESSION_KEY = 'lasuite-encryption/key-possession-key/v1';

// Fingerprints compared by people. Distinct so a device-pairing code can never
// match an identity, and the other way round.
export const DOMAIN_IDENTITY_FINGERPRINT = 'lasuite-encryption/identity-fingerprint/v1';
export const DOMAIN_DEVICE_PAIRING_FINGERPRINT = 'lasuite-encryption/device-pairing-fingerprint/v1';

// Associated data of AEAD ciphertexts. All but the device cache (WebCrypto
// AES-GCM) go through `encryptContent`, which only takes an `AeadDomain`.
export const DOMAIN_CONTENT = 'lasuite-encryption/content/v1';
export const DOMAIN_WRAPPED_KEY = 'lasuite-encryption/wrapped-key/v1';
export const DOMAIN_KEM_DOCUMENT_KEY = 'lasuite-encryption/kem-document-key/v1';
export const DOMAIN_KEM_DEVICE_BOOTSTRAP = 'lasuite-encryption/kem-device-bootstrap/v1';
export const DOMAIN_KEM_EMERGENCY_CAPSULE = 'lasuite-encryption/kem-emergency-capsule/v1';
export const DOMAIN_VAULT_ITEM = 'lasuite-encryption/vault-item/v1';
export const DOMAIN_VRK_WRAP = 'lasuite-encryption/vrk-wrap/v1';
export const DOMAIN_DEVICE_VRK = 'lasuite-encryption/device-vrk/v1';

// The only labels `encryptContent` and the X-Wing wrap accept, so a ciphertext
// cannot be sealed under an ad-hoc string or a label meant for something else.
export type AeadDomain =
  | typeof DOMAIN_CONTENT
  | typeof DOMAIN_WRAPPED_KEY
  | typeof DOMAIN_VAULT_ITEM
  | typeof DOMAIN_VRK_WRAP
  | typeof DOMAIN_KEM_DOCUMENT_KEY
  | typeof DOMAIN_KEM_DEVICE_BOOTSTRAP
  | typeof DOMAIN_KEM_EMERGENCY_CAPSULE;

// The subset that names what an X-Wing wrap carries.
export type KemWrapDomain = typeof DOMAIN_KEM_DOCUMENT_KEY | typeof DOMAIN_KEM_DEVICE_BOOTSTRAP | typeof DOMAIN_KEM_EMERGENCY_CAPSULE;

// The labels `deriveSubkey` accepts.
export type SubkeyDomain = typeof DOMAIN_VAULT_AUTH_SEED | typeof DOMAIN_VRK_WRAP_KEY | typeof DOMAIN_KEM_WRAP_KEY | typeof DOMAIN_KEY_POSSESSION_KEY;
