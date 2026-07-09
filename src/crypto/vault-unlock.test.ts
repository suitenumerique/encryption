import sodium from 'libsodium-wrappers-sumo';

import { detectMnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import {
  type KdfParams,
  deriveKek,
  deriveVaultAuthKeyPair,
  generateRecoveryPhrase,
  generateVrk,
  signAuthPublicKeyBinding,
  signVaultChallenge,
  unwrapVrk,
  verifyAuthPublicKeyBinding,
  verifyVaultChallenge,
  wrapVrk,
} from '@encryption/src/crypto/vault-unlock';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

// Cheap Argon2id params so the suite stays fast; correctness is independent of cost.
const FAST: KdfParams = { opsLimit: 1, memLimit: 8 * 1024 * 1024 };

const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

beforeAll(async () => {
  await sodium.ready;
});

describe('KEK derivation', () => {
  it('is deterministic for the same phrase and user', async () => {
    const a = await deriveKek(PHRASE, 'user-1', FAST);
    const b = await deriveKek(PHRASE, 'user-1', FAST);

    expect(a).toEqual(b);
    expect(a.length).toBe(32);
  });

  it('differs across users (salt = userId) and across phrases', async () => {
    const base = await deriveKek(PHRASE, 'user-1', FAST);

    expect(await deriveKek(PHRASE, 'user-2', FAST)).not.toEqual(base);
    expect(await deriveKek('other phrase entirely here', 'user-1', FAST)).not.toEqual(base);
  });

  it('tolerates hand-typed whitespace and case (normalization)', async () => {
    const base = await deriveKek(PHRASE, 'user-1', FAST);
    const messy = `  ${PHRASE.toUpperCase().replace(/ /g, '   ')}\n`;

    expect(await deriveKek(messy, 'user-1', FAST)).toEqual(base);
  });
});

describe('VRK wrap / unwrap', () => {
  it('round-trips under the right KEK', async () => {
    const kek = await deriveKek(PHRASE, 'user-1', FAST);
    const vrk = await generateVrk();

    const wrapped = await wrapVrk(vrk, kek);
    expect(await unwrapVrk(wrapped, kek)).toEqual(vrk);
  });

  it('rejects a wrong phrase with WRONG_SECRET_KEY', async () => {
    const kek = await deriveKek(PHRASE, 'user-1', FAST);
    const wrong = await deriveKek('a totally different recovery phrase value', 'user-1', FAST);
    const wrapped = await wrapVrk(await generateVrk(), kek);

    await expect(unwrapVrk(wrapped, wrong)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
  });
});

describe('passphrase proof of possession', () => {
  it('verifies a challenge signed with the derived auth key', async () => {
    const kek = await deriveKek(PHRASE, 'user-1', FAST);
    const auth = await deriveVaultAuthKeyPair(kek);
    const nonce = sodium.randombytes_buf(32);

    const sig = await signVaultChallenge(nonce, 'user-1', auth.secretKey);

    expect(await verifyVaultChallenge(nonce, 'user-1', sig, auth.publicKey)).toBe(true);
  });

  it('rejects a proof from the wrong phrase, nonce, or user', async () => {
    const auth = await deriveVaultAuthKeyPair(await deriveKek(PHRASE, 'user-1', FAST));
    const wrongAuth = await deriveVaultAuthKeyPair(await deriveKek('another phrase for the wrong key here', 'user-1', FAST));
    const nonce = sodium.randombytes_buf(32);
    const sig = await signVaultChallenge(nonce, 'user-1', auth.secretKey);

    expect(await verifyVaultChallenge(nonce, 'user-1', await signVaultChallenge(nonce, 'user-1', wrongAuth.secretKey), auth.publicKey)).toBe(false);
    expect(await verifyVaultChallenge(sodium.randombytes_buf(32), 'user-1', sig, auth.publicKey)).toBe(false);
    expect(await verifyVaultChallenge(nonce, 'user-2', sig, auth.publicKey)).toBe(false);
  });

  it('the auth key is a stable function of the KEK', async () => {
    const kek = await deriveKek(PHRASE, 'user-1', FAST);

    expect((await deriveVaultAuthKeyPair(kek)).publicKey).toEqual((await deriveVaultAuthKeyPair(kek)).publicKey);
  });
});

describe('auth public key binding', () => {
  it('verifies a binding signed by the identity, and rejects a wrong signer', async () => {
    const identity = await generateSignatureKeyPair();
    const rogue = await generateSignatureKeyPair();
    const authPublicKey = (await deriveVaultAuthKeyPair(await deriveKek(PHRASE, 'user-1', FAST))).publicKey;

    const sig = await signAuthPublicKeyBinding(authPublicKey, identity.secretKey);

    expect(await verifyAuthPublicKeyBinding(authPublicKey, sig, identity.publicKey)).toBe(true);
    expect(await verifyAuthPublicKeyBinding(authPublicKey, await signAuthPublicKeyBinding(authPublicKey, rogue.secretKey), identity.publicKey)).toBe(
      false
    );
  });

  it('is domain-separated: a raw signature over the key does not verify as a binding', async () => {
    const identity = await generateSignatureKeyPair();
    const authPublicKey = (await deriveVaultAuthKeyPair(await deriveKek(PHRASE, 'user-1', FAST))).publicKey;

    // A signature over the bare public key bytes (the pre-domain-separation format,
    // and the shape any other identity-key signature could coincide with) must not
    // pass the binding check.
    const raw = await signDetached(authPublicKey, identity.secretKey);

    expect(await verifyAuthPublicKeyBinding(authPublicKey, raw, identity.publicKey)).toBe(false);
  });
});

describe('generated recovery phrase', () => {
  it('is a 24-word phrase that unlocks a wrapped VRK end to end', async () => {
    const phrase = await generateRecoveryPhrase('english');
    expect(phrase.split(/\s+/)).toHaveLength(24);
    expect(detectMnemonicLanguage(phrase)).toBe('english');

    const kek = await deriveKek(phrase, 'user-1', FAST);
    const vrk = await generateVrk();
    const wrapped = await wrapVrk(vrk, kek);

    expect(await unwrapVrk(wrapped, kek)).toEqual(vrk);
  });

  it('is different every time', async () => {
    expect(await generateRecoveryPhrase('french')).not.toEqual(await generateRecoveryPhrase('french'));
  });
});

// keep the import used even if the matcher above is tweaked
void VaultError;
