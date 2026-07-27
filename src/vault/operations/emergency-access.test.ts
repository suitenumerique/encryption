import {
  type EmergencyEscrowRecord,
  sha256,
  signEmergencyEscrow,
  unwrapPhraseEntropy,
  verifyEmergencyEscrow,
  wrapPhraseEntropyForGrantee,
} from '@encryption/src/crypto/emergency-escrow';
import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { type MnemonicLanguage, keyToMnemonic, mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { generateRecoveryPhrase, signAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleCreateEmergencyEscrow, handleRevealEmergencyPhrase, handleVerifyEscrows } from '@encryption/src/vault/operations/emergency-access';
import { fetchContinuityChain, handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';
import { deriveKeyring, loadWithIdentity } from '@encryption/src/vault/operations/onboarding';

jest.mock('@encryption/src/vault/operations/fetch-public-keys');
jest.mock('@encryption/src/vault/operations/fingerprint-registry');
// The real deriveKeyring runs the full Argon2id KDF (64 MiB); the fake keeps
// the identical CONTRACT (fresh phrase, identity-bound auth key) at test speed.
jest.mock('@encryption/src/vault/operations/onboarding', () => ({
  loadWithIdentity: jest.fn(),
  deriveKeyring: jest.fn(),
}));

const mockFetchPublicKeys = handleFetchPublicKeys as jest.Mock;
const mockCheckFingerprints = handleCheckFingerprints as jest.Mock;
const mockFetchContinuityChain = fetchContinuityChain as jest.Mock;
const mockLoadWithIdentity = loadWithIdentity as jest.Mock;
const mockDeriveKeyring = deriveKeyring as jest.Mock;

const GRANTOR_ID = 'grantor-user';
const GRANTEE_ID = 'grantee-user';

type SigKeyPair = Awaited<ReturnType<typeof generateSignatureKeyPair>>;
type KemKeyPair = Awaited<ReturnType<typeof generateUserKeyPair>>;

const wireB64 = (pair: SigKeyPair) => exportPublicKeyAsBase64(pair.publicKey);

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

let grantorIdentity: SigKeyPair;
let granteeIdentity: SigKeyPair;
let granteeKem: KemKeyPair;

function directoryEntry(identity: SigKeyPair, kem: KemKeyPair, userId: string, overrides: Record<string, unknown> = {}) {
  return {
    userId,
    signaturePublicKey: toArrayBuffer(base64ToUint8(wireB64(identity))),
    identityFingerprint: '',
    version: 1,
    createdAtMillis: 1,
    verified: true,
    encryptionPublicKey: toArrayBuffer(base64ToUint8(exportPublicKeyAsBase64(kem.publicKey))),
    ...overrides,
  };
}

beforeEach(async () => {
  jest.clearAllMocks();
  grantorIdentity = await generateSignatureKeyPair();
  granteeIdentity = await generateSignatureKeyPair();
  granteeKem = await generateUserKeyPair();

  mockLoadWithIdentity.mockResolvedValue({
    loaded: {
      vrk: new Uint8Array(32).fill(1),
      state: {
        schema: 1,
        identities: [
          {
            generation: 1,
            algo: 'ed25519',
            signaturePublicKey: wireB64(grantorIdentity),
            signatureSecretKey: uint8ToBase64(grantorIdentity.secretKey),
            createdAt: 1,
          },
        ],
        encryptionKeys: [],
        active: { identityGen: 1, encKeyVersion: 1 },
        tofu: {},
      },
      cache: {},
    },
    identitySecret: grantorIdentity.secretKey,
  });

  mockDeriveKeyring.mockImplementation(async (_userId: string, _vrk: Uint8Array, identitySecret: Uint8Array, lang: MnemonicLanguage) => {
    const recoveryPhrase = await generateRecoveryPhrase(lang);
    const authKey = await generateSignatureKeyPair();

    return {
      recoveryPhrase,
      keyring: {
        wrapped_vrk: uint8ToBase64(new Uint8Array(48).fill(2)),
        auth_public_key: uint8ToBase64(authKey.publicKey),
        auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(authKey.publicKey, identitySecret)),
        kdf_ops: 3,
        kdf_mem: 64 * 1024 * 1024,
        lang,
      },
    };
  });

  const granteeEntry = directoryEntry(granteeIdentity, granteeKem, GRANTEE_ID, {
    identityFingerprint: await computeKeyFingerprint(wireB64(granteeIdentity)),
  });
  mockFetchPublicKeys.mockResolvedValue({ users: { [GRANTEE_ID]: granteeEntry } });
  mockCheckFingerprints.mockResolvedValue({ results: [{ userId: GRANTEE_ID, status: 'trusted' }] });
  mockFetchContinuityChain.mockResolvedValue([]);
});

describe('handleCreateEmergencyEscrow', () => {
  it('produces a designation whose signature verifies and whose capsule the contact can open', async () => {
    const body = await handleCreateEmergencyEscrow(GRANTOR_ID, { granteeUserId: GRANTEE_ID, waitTimeDays: 15, lang: 'english' });

    expect(body.grantee_user_id).toBe(GRANTEE_ID);
    expect(body.grantee_key_version).toBe(1);

    // The signed record must verify against the GRANTOR identity.
    const record: EmergencyEscrowRecord = {
      grantorUserId: GRANTOR_ID,
      granteeUserId: GRANTEE_ID,
      granteeIdentityPublicKeyWire: base64ToUint8(body.grantee_identity_public_key),
      waitTimeDays: 15,
      escrowCreatedAtMillis: body.escrow_created_at_millis,
      credentialAuthPublicKeyHash: await sha256(base64ToUint8(body.credential.auth_public_key)),
      capsuleHash: await sha256(base64ToUint8(body.wrapped_phrase_for_grantee)),
    };
    await expect(
      verifyEmergencyEscrow(record, base64ToUint8(body.escrow_signature), importPublicKeyFromBytes(base64ToUint8(wireB64(grantorIdentity))))
    ).resolves.toBe(true);

    // The capsule opens with the contact's private key to 32 bytes of entropy.
    const entropy = await unwrapPhraseEntropy(base64ToUint8(body.wrapped_phrase_for_grantee), [granteeKem.secretKey]);
    expect(entropy.length).toBe(32);
  });

  it('refuses an unknown (merely seen, never verified) contact: escrow demands explicit trust', async () => {
    mockCheckFingerprints.mockResolvedValue({ results: [{ userId: GRANTEE_ID, status: 'unknown' }] });

    await expect(handleCreateEmergencyEscrow(GRANTOR_ID, { granteeUserId: GRANTEE_ID, waitTimeDays: 15 })).rejects.toMatchObject({
      code: VaultErrorCode.UNTRUSTED_RECIPIENT,
    });
  });

  it('refuses a contact whose directory record does not verify', async () => {
    mockFetchPublicKeys.mockResolvedValue({
      users: { [GRANTEE_ID]: directoryEntry(granteeIdentity, granteeKem, GRANTEE_ID, { verified: false, encryptionPublicKey: null }) },
    });

    await expect(handleCreateEmergencyEscrow(GRANTOR_ID, { granteeUserId: GRANTEE_ID, waitTimeDays: 15 })).rejects.toMatchObject({
      code: VaultErrorCode.UNTRUSTED_RECIPIENT,
    });
  });
});

describe('handleVerifyEscrows', () => {
  async function trustedEntry(overrides: { waitTimeDays?: number; signer?: SigKeyPair; pinned?: SigKeyPair } = {}) {
    const waitTimeDays = overrides.waitTimeDays ?? 15;
    const signer = overrides.signer ?? grantorIdentity;
    const pinned = overrides.pinned ?? granteeIdentity;
    const capsule = new Uint8Array(64).fill(3);
    const authPub = new Uint8Array(32).fill(4);
    const escrowCreatedAtMillis = 1750000000000;

    const record: EmergencyEscrowRecord = {
      grantorUserId: GRANTOR_ID,
      granteeUserId: GRANTEE_ID,
      granteeIdentityPublicKeyWire: base64ToUint8(wireB64(pinned)),
      waitTimeDays,
      escrowCreatedAtMillis,
      credentialAuthPublicKeyHash: await sha256(authPub),
      capsuleHash: await sha256(capsule),
    };

    return {
      id: '77777777-7777-4777-8777-777777777777',
      grantee_user_id: GRANTEE_ID,
      wait_time_days: waitTimeDays,
      escrow: {
        grantee_identity_public_key: uint8ToBase64(base64ToUint8(wireB64(pinned))),
        grantee_key_version: 1,
        wrapped_phrase_for_grantee: uint8ToBase64(capsule),
        escrow_signature: uint8ToBase64(await signEmergencyEscrow(record, signer.secretKey)),
        escrow_created_at_millis: escrowCreatedAtMillis,
        credential_auth_public_key_hash: uint8ToBase64(await sha256(authPub)),
      },
    };
  }

  it('reports ok for an authentic, current escrow', async () => {
    const { results } = await handleVerifyEscrows(GRANTOR_ID, { contacts: [await trustedEntry()] });

    expect(results[0].status).toBe('ok');
  });

  it('flags a row the grantor identity never signed as tampered', async () => {
    const rogue = await generateSignatureKeyPair();

    const { results } = await handleVerifyEscrows(GRANTOR_ID, { contacts: [await trustedEntry({ signer: rogue })] });

    expect(results[0].status).toBe('tampered');
  });

  it('flags a contact who reset to an unlinked identity as stale', async () => {
    const reset = await generateSignatureKeyPair();
    // The pinned identity is the OLD one; the directory now serves `reset`.
    mockFetchPublicKeys.mockResolvedValue({
      users: {
        [GRANTEE_ID]: directoryEntry(reset, granteeKem, GRANTEE_ID, { identityFingerprint: await computeKeyFingerprint(wireB64(reset)) }),
      },
    });

    const { results } = await handleVerifyEscrows(GRANTOR_ID, { contacts: [await trustedEntry()] });

    expect(results[0].status).toBe('stale-identity');
  });

  it('flags an escrow wrapped to an outdated encryption key version', async () => {
    mockFetchPublicKeys.mockResolvedValue({
      users: {
        [GRANTEE_ID]: directoryEntry(granteeIdentity, granteeKem, GRANTEE_ID, {
          identityFingerprint: await computeKeyFingerprint(wireB64(granteeIdentity)),
          version: 3,
        }),
      },
    });

    const { results } = await handleVerifyEscrows(GRANTOR_ID, { contacts: [await trustedEntry()] });

    expect(results[0].status).toBe('outdated-key');
  });
});

describe('handleRevealEmergencyPhrase', () => {
  async function releasedEscrow(contactKem: KemKeyPair, signer: SigKeyPair) {
    const phrase = await generateRecoveryPhrase('french');
    const entropy = mnemonicToKey(phrase, 'french');
    const capsule = await wrapPhraseEntropyForGrantee(entropy, contactKem.publicKey);
    const authPub = new Uint8Array(32).fill(5);
    const escrowCreatedAtMillis = 1750000000000;

    const record: EmergencyEscrowRecord = {
      grantorUserId: GRANTOR_ID,
      granteeUserId: GRANTEE_ID,
      granteeIdentityPublicKeyWire: base64ToUint8(wireB64(granteeIdentity)),
      waitTimeDays: 15,
      escrowCreatedAtMillis,
      credentialAuthPublicKeyHash: await sha256(authPub),
      capsuleHash: await sha256(capsule),
    };

    return {
      phrase,
      payload: {
        grantorUserId: GRANTOR_ID,
        lang: 'french' as const,
        waitTimeDays: 15,
        escrow: {
          grantee_identity_public_key: uint8ToBase64(base64ToUint8(wireB64(granteeIdentity))),
          grantee_key_version: 1,
          wrapped_phrase_for_grantee: uint8ToBase64(capsule),
          escrow_signature: uint8ToBase64(await signEmergencyEscrow(record, signer.secretKey)),
          escrow_created_at_millis: escrowCreatedAtMillis,
          credential_auth_public_key_hash: uint8ToBase64(await sha256(authPub)),
        },
      },
    };
  }

  // The revealing CONTACT's vault: their own encryption secret key history.
  function contactVault(kem: KemKeyPair) {
    mockLoadWithIdentity.mockResolvedValue({
      loaded: {
        vrk: new Uint8Array(32).fill(1),
        state: {
          schema: 1,
          identities: [],
          encryptionKeys: [
            {
              version: 1,
              algo: 'x-wing',
              publicKey: exportPublicKeyAsBase64(kem.publicKey),
              secretKey: uint8ToBase64(kem.secretKey),
              createdAt: 1,
            },
          ],
          active: { identityGen: 1, encKeyVersion: 1 },
          tofu: {},
        },
        cache: {},
      },
      identitySecret: granteeIdentity.secretKey,
    });
  }

  beforeEach(async () => {
    contactVault(granteeKem);
    // The directory serves the GRANTOR record; the contact has them pinned trusted.
    mockFetchPublicKeys.mockResolvedValue({
      users: {
        [GRANTOR_ID]: directoryEntry(grantorIdentity, granteeKem, GRANTOR_ID, {
          identityFingerprint: await computeKeyFingerprint(wireB64(grantorIdentity)),
        }),
      },
    });
    mockCheckFingerprints.mockResolvedValue({ results: [{ userId: GRANTOR_ID, status: 'trusted' }] });
  });

  it('renders the exact phrase the escrow was built from', async () => {
    const { phrase, payload } = await releasedEscrow(granteeKem, grantorIdentity);

    const result = await handleRevealEmergencyPhrase(GRANTEE_ID, payload);

    expect(result.recoveryPhrase).toBe(phrase);
    expect(keyToMnemonic(mnemonicToKey(result.recoveryPhrase, 'french'), 'french')).toBe(phrase);
  });

  it('fails closed when the grantor was never verified out-of-band', async () => {
    mockCheckFingerprints.mockResolvedValue({ results: [{ userId: GRANTOR_ID, status: 'unknown' }] });
    const { payload } = await releasedEscrow(granteeKem, grantorIdentity);

    await expect(handleRevealEmergencyPhrase(GRANTEE_ID, payload)).rejects.toMatchObject({ code: VaultErrorCode.UNTRUSTED_RECIPIENT });
  });

  it('rejects a server-forged escrow record (signature does not match the pinned grantor)', async () => {
    const rogue = await generateSignatureKeyPair();
    const { payload } = await releasedEscrow(granteeKem, rogue);

    await expect(handleRevealEmergencyPhrase(GRANTEE_ID, payload)).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
  });
});
