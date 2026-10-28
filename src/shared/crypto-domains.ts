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
// The recovery council (architecture.md Appendix F): a roster version, a user's escrow, a share
// handed to a recovery, the key a helper hands a new custodian when resharing,
// and the commitments a helper reshares under.
export const DOMAIN_COUNCIL_ROSTER = 'lasuite-encryption/council-roster/v1';
export const DOMAIN_COUNCIL_ESCROW = 'lasuite-encryption/council-escrow/v1';
export const DOMAIN_COUNCIL_CONTRIBUTION = 'lasuite-encryption/council-contribution/v1';
export const DOMAIN_COUNCIL_RESHARE_KEY_BINDING = 'lasuite-encryption/council-reshare-key-binding/v1';
export const DOMAIN_COUNCIL_RESHARE_COMMITMENTS = 'lasuite-encryption/council-reshare-commitments/v1';

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
// The maintenance escrow key, compared by its custodians against the server's boot log.
export const DOMAIN_MAINTENANCE_KEY_FINGERPRINT = 'lasuite-encryption/maintenance-key-fingerprint/v1';
// A council roster version, compared with the one its organization published, and
// the key a locked-out user's browser shows a custodian at the meeting.
export const DOMAIN_COUNCIL_FINGERPRINT = 'lasuite-encryption/council-fingerprint/v1';
export const DOMAIN_COUNCIL_REQUEST_FINGERPRINT = 'lasuite-encryption/council-request-fingerprint/v1';

// Hash commitment to the council's emergency secret, in its signed record and
// checked after combining: it hashes about 252 bits of uniform randomness, so it
// reveals nothing. The shares themselves are checked against Pedersen
// commitments, whose second generator is hashed to the group from this label.
export const DOMAIN_COUNCIL_SECRET_COMMITMENT = 'lasuite-encryption/council-secret-commitment/v1';
export const DOMAIN_COUNCIL_PEDERSEN_GENERATOR = 'lasuite-encryption/council-pedersen-generator/v1';

// Associated data of AEAD ciphertexts. All but the device cache (WebCrypto
// AES-GCM) go through `encryptContent`, which only takes an `AeadDomain`.
export const DOMAIN_CONTENT = 'lasuite-encryption/content/v1';
export const DOMAIN_WRAPPED_KEY = 'lasuite-encryption/wrapped-key/v1';
export const DOMAIN_KEM_DOCUMENT_KEY = 'lasuite-encryption/kem-document-key/v1';
export const DOMAIN_KEM_DEVICE_BOOTSTRAP = 'lasuite-encryption/kem-device-bootstrap/v1';
export const DOMAIN_KEM_EMERGENCY_CAPSULE = 'lasuite-encryption/kem-emergency-capsule/v1';
// A resource key wrapped for the deployment's maintenance escrow key, apart from a
// user's copy so that neither can ever be accepted as the other.
export const DOMAIN_KEM_MAINTENANCE_KEY = 'lasuite-encryption/kem-maintenance-key/v1';
// A council share wrapped for its custodian, a share handed to a recovery (wrapped
// for the locked-out browser's ephemeral key), a resharing transfer key wrapped
// for a new custodian, and a sub-share sealed under that transfer key.
export const DOMAIN_KEM_COUNCIL_SHARE = 'lasuite-encryption/kem-council-share/v1';
export const DOMAIN_KEM_COUNCIL_TRANSFER = 'lasuite-encryption/kem-council-transfer/v1';
export const DOMAIN_KEM_COUNCIL_RESHARE_KEY = 'lasuite-encryption/kem-council-reshare-key/v1';
export const DOMAIN_COUNCIL_SUBSHARE = 'lasuite-encryption/council-subshare/v1';
// A helper's resharing transfer keys, derived from its VRK per session and
// recipient so a reload finds the same ones again.
export const DOMAIN_COUNCIL_TRANSFER_KEY = 'lasuite-encryption/council-transfer-key/v1';
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
  | typeof DOMAIN_KEM_EMERGENCY_CAPSULE
  | typeof DOMAIN_KEM_MAINTENANCE_KEY
  | typeof DOMAIN_KEM_COUNCIL_SHARE
  | typeof DOMAIN_KEM_COUNCIL_TRANSFER
  | typeof DOMAIN_KEM_COUNCIL_RESHARE_KEY
  | typeof DOMAIN_COUNCIL_SUBSHARE;

// The subset that names what an X-Wing wrap carries.
export type KemWrapDomain =
  | typeof DOMAIN_KEM_DOCUMENT_KEY
  | typeof DOMAIN_KEM_DEVICE_BOOTSTRAP
  | typeof DOMAIN_KEM_EMERGENCY_CAPSULE
  | typeof DOMAIN_KEM_MAINTENANCE_KEY
  | typeof DOMAIN_KEM_COUNCIL_SHARE
  | typeof DOMAIN_KEM_COUNCIL_TRANSFER
  | typeof DOMAIN_KEM_COUNCIL_RESHARE_KEY;

// The labels `deriveSubkey` accepts.
export type SubkeyDomain =
  | typeof DOMAIN_VAULT_AUTH_SEED
  | typeof DOMAIN_VRK_WRAP_KEY
  | typeof DOMAIN_KEM_WRAP_KEY
  | typeof DOMAIN_KEY_POSSESSION_KEY
  | typeof DOMAIN_COUNCIL_TRANSFER_KEY;
