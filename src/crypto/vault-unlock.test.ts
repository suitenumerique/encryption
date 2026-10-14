import sodium from 'libsodium-wrappers-sumo';
import { beforeAll, describe, expect, it } from 'vitest';

import { encryptContent } from '@encryption/src/crypto/encryption';
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
import { DOMAIN_VRK_WRAP } from '@encryption/src/shared/crypto-domains';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

// Cheap Argon2id params so the suite stays fast; correctness is independent of cost.
const FAST: KdfParams = { opsLimit: 1, memLimit: 8 * 1024 * 1024 };

const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

const seq = (length: number, start = 0) => Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

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

  it('never seals under the KEK itself, only under its wrapping subkey', async () => {
    const kek = await deriveKek(PHRASE, 'user-1', FAST);
    const directlyUnderKek = await encryptContent(await generateVrk(), kek, DOMAIN_VRK_WRAP);

    await expect(unwrapVrk(directlyUnderKek, kek)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
  });
});

// Known answers: a recovery phrase must keep unlocking the same vault, so the
// salt label, the KEK subkeys and the wrap's associated data must never drift.
describe('vault unlock (known answers)', () => {
  it('derives the known KEK for a phrase and user', async () => {
    expect(hex(await deriveKek(PHRASE, 'user-1', FAST))).toBe('6625b3d6be5d66cc7fbef3dd1b562f6ba9be56c1388e4524df12f4103cd8bde9');
  });

  it('opens the known wrapped VRK', async () => {
    expect(
      await unwrapVrk(
        Uint8Array.from(
          Buffer.from(
            '01749912e631818075cf3be8024cf327fb9e9526100b69d875e61e89b4c298c4d4ec20d93c116fc6fd6ad7aa6562f033949d3e747986222a419766afd2fa7918cf5c68733ee76514fd',
            'hex'
          )
        ),
        seq(32)
      )
    ).toEqual(seq(32, 200));
  });

  it('derives the known auth public key', async () => {
    expect(hex((await deriveVaultAuthKeyPair(seq(32))).publicKey)).toBe('d46163922905bcfd622b8112737187353948e9dc875b8eab0900db37967fdc6a');
  });

  // Ed25519 is deterministic, so a fixed key over fixed inputs pins the signed
  // bytes: framed label, framed user id, framed nonce.
  it('signs the known unlock challenge', async () => {
    const signer = sodium.crypto_sign_seed_keypair(seq(32));

    expect(hex(await signVaultChallenge(seq(32, 50), 'user-1', signer.privateKey))).toBe(
      '16c2e923461e8a6294e6ceb5b2a9276910319204065426400cfeb60beb65e9ee18205d4900e39b806156735923ad0df87f42a6be3a3da6dae42c3f2798a35f03'
    );
  });

  it('signs the known auth-key binding', async () => {
    const signer = sodium.crypto_sign_seed_keypair(seq(32));

    expect(hex(await signAuthPublicKeyBinding(seq(32, 100), signer.privateKey))).toBe(
      '84a6b8a92cd793ce2e900cc812cbc21e1db46d78791911cc70e132f474d3958ccdaa675bc263d906cf99c7a5162caf97d1ce6de95b88d821f0f477c088a2bf02'
    );
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
