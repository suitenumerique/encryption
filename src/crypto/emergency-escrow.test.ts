import {
  type EmergencyEscrowRecord,
  encodeEmergencyEscrowPayload,
  sha256,
  signEmergencyEscrow,
  unwrapPhraseEntropy,
  verifyEmergencyEscrow,
  wrapPhraseEntropyForGrantee,
} from '@encryption/src/crypto/emergency-escrow';
import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { generateRecoveryPhrase } from '@encryption/src/crypto/vault-unlock';

describe('emergency escrow binding signature', () => {
  async function record(overrides: Partial<EmergencyEscrowRecord> = {}): Promise<EmergencyEscrowRecord> {
    return {
      grantorUserId: '11111111-1111-4111-8111-111111111111',
      granteeUserId: '22222222-2222-4222-8222-222222222222',
      granteeIdentityPublicKeyWire: new Uint8Array(33).fill(7),
      waitTimeDays: 15,
      escrowCreatedAtMillis: 1750000000000,
      credentialAuthPublicKeyHash: await sha256(new Uint8Array(32).fill(1)),
      capsuleHash: await sha256(new Uint8Array(100).fill(2)),
      ...overrides,
    };
  }

  it('signs and verifies a record', async () => {
    const identity = await generateSignatureKeyPair();
    const r = await record();

    const signature = await signEmergencyEscrow(r, identity.secretKey);

    await expect(verifyEmergencyEscrow(r, signature, identity.publicKey)).resolves.toBe(true);
  });

  it('rejects any tampered field', async () => {
    const identity = await generateSignatureKeyPair();
    const r = await record();
    const signature = await signEmergencyEscrow(r, identity.secretKey);

    const tampered: EmergencyEscrowRecord[] = [
      await record({ waitTimeDays: 7 }),
      await record({ granteeUserId: '33333333-3333-4333-8333-333333333333' }),
      await record({ escrowCreatedAtMillis: 1750000000001 }),
      await record({ granteeIdentityPublicKeyWire: new Uint8Array(33).fill(8) }),
      await record({ credentialAuthPublicKeyHash: await sha256(new Uint8Array(32).fill(9)) }),
      await record({ capsuleHash: await sha256(new Uint8Array(100).fill(9)) }),
    ];

    for (const t of tampered) {
      await expect(verifyEmergencyEscrow(t, signature, identity.publicKey)).resolves.toBe(false);
    }
  });

  it('rejects a signature from a different identity', async () => {
    const identity = await generateSignatureKeyPair();
    const other = await generateSignatureKeyPair();
    const r = await record();

    const signature = await signEmergencyEscrow(r, other.secretKey);

    await expect(verifyEmergencyEscrow(r, signature, identity.publicKey)).resolves.toBe(false);
  });

  it('length-frames fields so adjacent values cannot be spliced', async () => {
    // Moving a byte across a field boundary must change the encoding: framing
    // includes each field's length, so 'ab' + 'c' differs from 'a' + 'bc'.
    const a = encodeEmergencyEscrowPayload(await record({ grantorUserId: 'ab', granteeUserId: 'c' }));
    const b = encodeEmergencyEscrowPayload(await record({ grantorUserId: 'a', granteeUserId: 'bc' }));

    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe('emergency phrase capsule', () => {
  it('round-trips the phrase entropy through the contact key', async () => {
    const grantee = await generateUserKeyPair();
    const phrase = await generateRecoveryPhrase('english');
    const entropy = mnemonicToKey(phrase, 'english');

    const capsule = await wrapPhraseEntropyForGrantee(entropy, grantee.publicKey);
    const opened = await unwrapPhraseEntropy(capsule, [grantee.secretKey]);

    expect(Buffer.from(opened).equals(Buffer.from(entropy))).toBe(true);
  });

  it('opens with an older key in the history (contact rotated since designation)', async () => {
    const oldKey = await generateUserKeyPair();
    const newKey = await generateUserKeyPair();
    const entropy = mnemonicToKey(await generateRecoveryPhrase('french'), 'french');

    const capsule = await wrapPhraseEntropyForGrantee(entropy, oldKey.publicKey);
    // Newest first, like the vault's grow-only key history is walked.
    const opened = await unwrapPhraseEntropy(capsule, [newKey.secretKey, oldKey.secretKey]);

    expect(Buffer.from(opened).equals(Buffer.from(entropy))).toBe(true);
  });

  it('throws when no key in the history opens the capsule', async () => {
    const grantee = await generateUserKeyPair();
    const stranger = await generateUserKeyPair();
    const entropy = mnemonicToKey(await generateRecoveryPhrase('english'), 'english');

    const capsule = await wrapPhraseEntropyForGrantee(entropy, grantee.publicKey);

    await expect(unwrapPhraseEntropy(capsule, [stranger.secretKey])).rejects.toBeTruthy();
  });
});
