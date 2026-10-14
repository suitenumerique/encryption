/**
 * Turning the recovery phrase into the keys that unlock the vault.
 *
 *   KEK  = Argon2id(recovery phrase, salt = BLAKE2b(salt label | userId))
 *   VRK  = random 32 bytes, wrapped by a subkey of the KEK -> wrappedVRK stored on the server
 *   auth = Ed25519 key pair seeded by another subkey of the KEK
 *
 * The VRK actually encrypts the vault items; the KEK only wraps it, so changing
 * the recovery phrase re-wraps one key instead of re-encrypting the vault. The
 * auth key proves possession of the phrase before the server releases the
 * wrappedVRK (see the cold-unlock flow); its public half is a passphrase-derived
 * verifier and is never handed to a client.
 *
 * The salt is `userId`. It is not secret: only the client runs the KDF, so a
 * tampered salt just yields a wrong KEK and a detectable unwrap failure, not a
 * disclosure. libsodium has no HKDF, so each subkey is a BLAKE2b keyed by the KEK
 * over its own label: the KEK itself never keys a primitive, so the wrapping key
 * and the auth seed stay independent.
 */
import sodium from 'libsodium-wrappers-sumo';

import { concat, decryptContent, deriveSubkey, encryptContent, ensureSodium, lengthPrefixed } from '@encryption/src/crypto/encryption';
import { type MnemonicLanguage, keyToMnemonic } from '@encryption/src/crypto/mnemonic';
import { type SignatureKeyPair, signDetached, verifyDetached } from '@encryption/src/crypto/signature';
import {
  DOMAIN_VAULT_AUTH_BINDING,
  DOMAIN_VAULT_AUTH_CHALLENGE,
  DOMAIN_VAULT_AUTH_SEED,
  DOMAIN_VAULT_KDF_SALT,
  DOMAIN_VRK_WRAP,
  DOMAIN_VRK_WRAP_KEY,
} from '@encryption/src/shared/crypto-domains';

export interface KdfParams {
  opsLimit: number;
  memLimit: number;
}

// Argon2id cost. The phrase is high-entropy, so this is defense-in-depth; the
// params live in the keyring so they can be raised later without guesswork.
export const DEFAULT_KDF_PARAMS: KdfParams = { opsLimit: 3, memLimit: 64 * 1024 * 1024 };

function deriveKdfSalt(userId: string): Uint8Array {
  return sodium.crypto_generichash(sodium.crypto_pwhash_SALTBYTES, sodium.from_string(`${DOMAIN_VAULT_KDF_SALT}|${userId}`), null);
}

function deriveVrkWrapKey(kek: Uint8Array): Uint8Array {
  return deriveSubkey(kek, DOMAIN_VRK_WRAP_KEY, sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

/**
 * Canonicalize a recovery phrase before it feeds the KDF, so it derives the same
 * KEK whether it was typed with stray/leading/trailing spaces or a different
 * case. Idempotent on a freshly generated phrase (already lowercase, single-
 * spaced), so it never changes the KEK for a vault created by this code — it only
 * makes hand-typed restore input tolerant. BIP-39 words are compared NFKD, which
 * also keeps accented French words consistent between generate and restore.
 */
export function normalizeRecoveryPhrase(phrase: string): string {
  return phrase.normalize('NFKD').trim().replace(/\s+/g, ' ').toLowerCase();
}

export async function deriveKek(recoveryPhrase: string, userId: string, params: KdfParams = DEFAULT_KDF_PARAMS): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.crypto_pwhash(
    32,
    normalizeRecoveryPhrase(recoveryPhrase),
    deriveKdfSalt(userId),
    params.opsLimit,
    params.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

export async function generateVrk(): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.randombytes_buf(32);
}

/**
 * A generated, high-entropy recovery phrase: 32 random bytes rendered as a
 * 24-word BIP-39 mnemonic in the chosen wordlist. Its entropy, not the KDF, is
 * what keeps a leaked wrappedVRK unbruteforceable, so it is never user-chosen.
 */
export async function generateRecoveryPhrase(language: MnemonicLanguage = 'english'): Promise<string> {
  await ensureSodium();

  return keyToMnemonic(sodium.randombytes_buf(32), language);
}

export async function wrapVrk(vrk: Uint8Array, kek: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return encryptContent(vrk, deriveVrkWrapKey(kek), DOMAIN_VRK_WRAP);
}

/** Throws VaultErrorCode.WRONG_SECRET_KEY when the phrase (hence the KEK) is wrong. */
export async function unwrapVrk(wrapped: Uint8Array, kek: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return decryptContent(wrapped, deriveVrkWrapKey(kek), DOMAIN_VRK_WRAP);
}

export async function deriveVaultAuthKeyPair(kek: Uint8Array): Promise<SignatureKeyPair> {
  await ensureSodium();

  const seed = deriveSubkey(kek, DOMAIN_VAULT_AUTH_SEED, sodium.crypto_sign_SEEDBYTES);
  const kp = sodium.crypto_sign_seed_keypair(seed);

  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

function challengeMessage(nonce: Uint8Array, userId: string): Uint8Array {
  return concat([
    ...lengthPrefixed(sodium.from_string(DOMAIN_VAULT_AUTH_CHALLENGE)),
    ...lengthPrefixed(sodium.from_string(userId)),
    ...lengthPrefixed(nonce),
  ]);
}

export async function signVaultChallenge(nonce: Uint8Array, userId: string, authSecretKey: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return signDetached(challengeMessage(nonce, userId), authSecretKey);
}

export async function verifyVaultChallenge(nonce: Uint8Array, userId: string, signature: Uint8Array, authPublicKey: Uint8Array): Promise<boolean> {
  await ensureSodium();

  return verifyDetached(signature, challengeMessage(nonce, userId), authPublicKey);
}

/**
 * The message the identity signs to bind a keyring's auth public key. It is
 * domain-separated (context tag) and length-framed, so this signature can never
 * coincide with any other message the same identity key signs (the unlock
 * challenge, a key registration, a continuity endorsement) and none of those can
 * be replayed as an auth binding. The identity key is globally unique per user,
 * so binding the key alone already ties the keyring to one user; no userId field
 * is needed. Framing each field with a length prefix keeps the boundary between
 * context and key unambiguous.
 */
function authBindingMessage(authPublicKey: Uint8Array): Uint8Array {
  return concat([...lengthPrefixed(sodium.from_string(DOMAIN_VAULT_AUTH_BINDING)), ...lengthPrefixed(authPublicKey)]);
}

/** Identity signs the domain-separated binding over a keyring's auth public key. */
export async function signAuthPublicKeyBinding(authPublicKey: Uint8Array, identitySecretKey: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return signDetached(authBindingMessage(authPublicKey), identitySecretKey);
}

/**
 * Verify that a keyring's `authPublicKey` is genuinely bound to the identity:
 * `authPubSig` must be the identity's Ed25519 signature over the domain-separated
 * binding message (see `signAuthPublicKeyBinding`). Enforcing this server-side
 * stops a token-thief from writing a keyring whose auth verifier they control,
 * which would otherwise let them pass the unlock PoP gate and pull the
 * brute-forceable `wrappedVrk`. `identityPublicKey` is the raw Ed25519 key
 * (version byte already stripped).
 */
export async function verifyAuthPublicKeyBinding(authPublicKey: Uint8Array, authPubSig: Uint8Array, identityPublicKey: Uint8Array): Promise<boolean> {
  await ensureSodium();

  return verifyDetached(authPubSig, authBindingMessage(authPublicKey), identityPublicKey);
}
