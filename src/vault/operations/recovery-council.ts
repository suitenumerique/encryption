/**
 * Recovery council vault operations (shamir.md). All privileged (interface only):
 * each one is a decision a person takes on a screen of the interface, never
 * something a product page can trigger.
 *
 * What the vault trusts, and why:
 * - a roster version only through the signed chain (src/crypto/council.ts),
 *   from version 1 or from the version the user's own signed escrow names;
 * - a custodian's encryption key only when the directory binding verifies AND
 *   the identity behind it is the one the roster pins;
 * - a newcomer to a council only once the signing custodian marked their
 *   fingerprint `trusted` (checked out of band);
 * - the locked-out browser's ephemeral key, for the last share, only when it
 *   matches the code the custodian read on the person's own screen.
 */
import { requestFingerprint, rosterFingerprint, rosterHash, signRoster, verifyEscrow, verifyRosterChain } from '@encryption/src/crypto/council';
import type { RosterRecord } from '@encryption/src/crypto/council';
import {
  buildContribution,
  buildCouncilEscrow,
  buildReshareKeys,
  buildReshareSubShares,
  escrowRecordFromWire,
  openCustodianShare,
  recoverCouncilSecret,
  rosterRecordFromWire,
  signedVersionFromWire,
} from '@encryption/src/crypto/council-protocol';
import { ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { type MnemonicLanguage, keyToMnemonic } from '@encryption/src/crypto/mnemonic';
import { randomScalar } from '@encryption/src/crypto/shamir';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { STORE_COUNCIL_REQUEST } from '@encryption/src/shared/constants';
import { normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import type {
  CouncilCapsuleWire,
  CouncilContributionBody,
  CouncilEscrowBody,
  CouncilEscrowRecordWire,
  CouncilReleasedShares,
  CouncilReshareBatch,
  CouncilReshareKeysBody,
  CouncilReshareSubSharesBody,
  RosterVersionWire,
} from '@encryption/src/shared/schemas/recovery-council';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';
import { deriveKeyring, loadWithIdentity } from '@encryption/src/vault/operations/onboarding';
import { handleReactivateVault, handleRestoreFromPhrase } from '@encryption/src/vault/operations/vault-restore';

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

async function verifiedHead(councilId: string, chain: RosterVersionWire[], anchorHash?: string): Promise<RosterRecord> {
  const result = await verifyRosterChain(
    chain.map((v) => signedVersionFromWire(councilId, v)),
    anchorHash ? base64ToUint8(anchorHash) : undefined
  );

  if (!result.ok) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, `The council's membership could not be verified (${result.reason}).`);
  }

  return result.head;
}

/** Each member's encryption key, accepted only when its directory binding verifies under the identity the roster pins. */
async function membersKeys(userId: string, roster: RosterRecord): Promise<Map<number, Uint8Array>> {
  const { users } = await handleFetchPublicKeys(userId, { userIds: roster.members.map((m) => m.userId) });
  const keys = new Map<number, Uint8Array>();

  for (const member of roster.members) {
    const entry = users[member.userId];

    if (!entry || !entry.verified || !entry.encryptionPublicKey || !equal(new Uint8Array(entry.signaturePublicKey), member.identityPublicKeyWire)) {
      throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'A custodian’s keys do not match the identity the council pins.');
    }

    keys.set(member.slot, importPublicKeyFromBytes(new Uint8Array(entry.encryptionPublicKey)));
  }

  return keys;
}

// ----- The user ------------------------------------------------------------------

/** The head of a council and the 40 digits its organization publishes for it. */
export async function handleVerifyCouncilRoster(
  _userId: string,
  payload: { councilId: string; chain: RosterVersionWire[]; anchorHash?: string }
): Promise<{ version: number; fingerprint: string }> {
  const head = await verifiedHead(payload.councilId, payload.chain, payload.anchorHash);

  return { version: head.version, fingerprint: await rosterFingerprint(head) };
}

/**
 * Enroll, re-enroll, or re-arm after a recovery: a fresh dormant phrase, its
 * credential, split over the head of the verified chain. Without an anchor the
 * chain is verified from version 1 (the user has just compared the head's
 * fingerprint); with one, from the version the user's own escrow pinned.
 */
export async function handleCreateCouncilEscrow(
  userId: string,
  payload: { councilId: string; chain: RosterVersionWire[]; anchorHash?: string; lang?: MnemonicLanguage }
): Promise<CouncilEscrowBody> {
  const { loaded, identitySecret } = await loadWithIdentity(userId);
  const head = await verifiedHead(payload.councilId, payload.chain, payload.anchorHash);
  const custodianKeys = await membersKeys(userId, head);

  await ensureSodium();
  const secret = randomScalar();
  const lang = payload.lang ?? 'english';
  const { keyring } = await deriveKeyring(userId, loaded.vrk, identitySecret, lang, keyToMnemonic(secret, lang));

  try {
    return await buildCouncilEscrow({
      userId,
      head,
      custodianKeys,
      secret,
      credential: keyring,
      identitySecretKey: identitySecret,
      createdAtMillis: Date.now(),
    });
  } finally {
    secret.fill(0);
  }
}

export type CouncilEscrowCheck = 'ok' | 'tampered' | 'chain-broken';

/**
 * Audit what the server says of the user's escrow: signed by their identity, and
 * the council's current head reachable from the version it pins. A broken chain
 * means a membership nobody legitimately signed: nothing is re-armed onto it.
 */
export async function handleCheckCouncilEscrow(
  userId: string,
  payload: { record: CouncilEscrowRecordWire; chain: RosterVersionWire[] }
): Promise<{ status: CouncilEscrowCheck; headFingerprint: string | null }> {
  const { loaded } = await loadWithIdentity(userId);
  const identity = activeIdentity(loaded.state)!;

  const signed = await verifyEscrow(
    escrowRecordFromWire(userId, payload.record),
    base64ToUint8(payload.record.escrow_signature),
    base64ToUint8(identity.signaturePublicKey)
  );
  if (!signed) return { status: 'tampered', headFingerprint: null };

  const chain = await verifyRosterChain(
    payload.chain.map((v) => signedVersionFromWire(payload.record.council_id, v)),
    base64ToUint8(payload.record.roster_hash)
  );
  if (!chain.ok) return { status: 'chain-broken', headFingerprint: null };

  return { status: 'ok', headFingerprint: await rosterFingerprint(chain.head) };
}

// ----- The locked-out browser --------------------------------------------------

interface StoredRequestKey {
  publicKey: string; // wire base64
  secretKey: Uint8Array;
  createdAtMillis: number;
}

async function readRequestKey(userId: string): Promise<StoredRequestKey | null> {
  const db = await getEncryptionDB();

  return ((await db.get(STORE_COUNCIL_REQUEST, userId)) as StoredRequestKey | undefined) ?? null;
}

async function deleteRequestKey(userId: string): Promise<void> {
  const db = await getEncryptionDB();
  await db.delete(STORE_COUNCIL_REQUEST, userId);
}

/** A fresh ephemeral key for a new request; its secret half stays in this browser's store. */
export async function handleStartCouncilRequest(userId: string): Promise<{ ephemeralPublicKey: string; fingerprint: string }> {
  const pair = await generateUserKeyPair();
  const publicKey = exportPublicKeyAsBase64(pair.publicKey);

  const db = await getEncryptionDB();
  await db.put(STORE_COUNCIL_REQUEST, { publicKey, secretKey: pair.secretKey, createdAtMillis: Date.now() } satisfies StoredRequestKey, userId);

  return { ephemeralPublicKey: publicKey, fingerprint: await requestFingerprint(base64ToUint8(publicKey)) };
}

/** The key of the request this browser opened, for the meeting screen (null on another browser). */
export async function handleCouncilRequestKey(userId: string): Promise<{ ephemeralPublicKey: string; fingerprint: string } | null> {
  const stored = await readRequestKey(userId);
  if (!stored) return null;

  return { ephemeralPublicKey: stored.publicKey, fingerprint: await requestFingerprint(base64ToUint8(stored.publicKey)) };
}

// Held between a recovery that unlocked a superseded vault and the user's
// confirmation to bring it back; never stored, gone with the page.
const pendingReactivation = new Map<string, string>();

/**
 * Rebuild the dormant phrase from the released shares, in this browser only,
 * and unlock with it. The phrase is never shown: it is used once, here, and the
 * interface goes straight to the forced change of the user's own phrase.
 */
export async function handleCompleteCouncilRecovery(
  userId: string,
  payload: { released: CouncilReleasedShares; idToken: string }
): Promise<{
  publicKey: string;
  signaturePublicKey: string;
  isActiveVault: boolean;
  vaultCreatedAtMillis: number;
  contributors: Array<{ name: string | null; inPerson: boolean }>;
}> {
  const stored = await readRequestKey(userId);
  if (!stored) throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'This browser did not open the recovery request.');

  const { users } = await handleFetchPublicKeys(userId, { userIds: [userId] });
  const self = users[userId];
  if (!self || !self.verified) throw new VaultError(VaultErrorCode.INVALID_KEY_BINDING, 'Your own directory record does not verify.');

  let recovered;
  try {
    recovered = await recoverCouncilSecret(
      payload.released,
      { publicKey: base64ToUint8(stored.publicKey), secretKey: stored.secretKey },
      new Uint8Array(self.signaturePublicKey)
    );
  } catch (err) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, (err as Error).message);
  }

  const phrase = keyToMnemonic(recovered.secret, payload.released.lang as MnemonicLanguage);
  recovered.secret.fill(0);

  const restored = await handleRestoreFromPhrase(userId, { recoveryPhrase: phrase, idToken: payload.idToken });
  await deleteRequestKey(userId);

  if (!restored.isActiveVault) pendingReactivation.set(userId, phrase);

  return {
    publicKey: restored.publicKey,
    signaturePublicKey: restored.signaturePublicKey,
    isActiveVault: restored.isActiveVault,
    vaultCreatedAtMillis: restored.vaultCreatedAtMillis,
    contributors: recovered.contributors.map((c) => ({ name: c.name, inPerson: c.inPerson })),
  };
}

/** The user confirmed bringing back the superseded vault the council recovered. */
export async function handleReactivateCouncilVault(
  userId: string,
  payload: { idToken: string }
): Promise<{ publicKey: string; signaturePublicKey: string }> {
  const phrase = pendingReactivation.get(userId);
  if (!phrase) throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No recovered vault waits to be brought back.');

  const result = await handleReactivateVault(userId, { recoveryPhrase: phrase, idToken: payload.idToken });
  pendingReactivation.delete(userId);

  return { publicKey: result.publicKey, signaturePublicKey: result.signaturePublicKey };
}

// ----- A custodian ----------------------------------------------------------------

export interface CustodianRequestDetail {
  id: string;
  council_id: string;
  user_id: string;
  ephemeral_public_key: string;
  escrow: CouncilEscrowRecordWire;
  capsule: CouncilCapsuleWire;
}

/**
 * Hand over this custodian's share. In person, the share goes only to the key
 * whose code the custodian read on the person's screen: a key swapped by the
 * server, or a request opened by someone else, is refused here.
 */
export async function handleCouncilContribute(
  userId: string,
  payload: { detail: CustodianRequestDetail; inPerson: boolean; meetingCode?: string }
): Promise<CouncilContributionBody> {
  const { loaded, identitySecret } = await loadWithIdentity(userId);
  const { detail } = payload;
  const ephemeral = base64ToUint8(detail.ephemeral_public_key);

  if (payload.inPerson) {
    const expected = normalizeDecimalFingerprint(payload.meetingCode ?? '');
    if (expected !== (await requestFingerprint(ephemeral))) {
      throw new VaultError(VaultErrorCode.INVALID_KEY_BINDING, 'The code does not match the one of this request.');
    }
  }

  // The escrow is the user's: it must verify under their directory identity.
  const { users } = await handleFetchPublicKeys(userId, { userIds: [detail.user_id] });
  const owner = users[detail.user_id];
  const record = escrowRecordFromWire(detail.user_id, detail.escrow);
  if (
    !owner ||
    !owner.verified ||
    !(await verifyEscrow(record, base64ToUint8(detail.escrow.escrow_signature), new Uint8Array(owner.signaturePublicKey)))
  ) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The escrow is not signed by the person asking.');
  }

  const secretKeys = [...loaded.state.encryptionKeys].sort((a, b) => b.version - a.version).map((k) => base64ToUint8(k.secretKey));
  let share: Uint8Array;
  try {
    share = await openCustodianShare(detail.capsule, record, { userId: detail.user_id, councilId: detail.council_id, secretKeys });
  } catch (err) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, (err as Error).message);
  }

  try {
    return await buildContribution({
      requestId: detail.id,
      userId: detail.user_id,
      councilId: detail.council_id,
      slot: detail.capsule.slot,
      custodianUserId: userId,
      ephemeralPublicKey: ephemeral,
      encodedShare: share,
      inPerson: payload.inPerson,
      identitySecretKey: identitySecret,
    });
  } finally {
    share.fill(0);
  }
}

/**
 * Sign a proposed roster version. The proposal must extend the verified chain,
 * name this custodian with their own key if it names them, and every person it
 * adds (other than this custodian) must have been checked out of band first:
 * that check is what stops a server from slipping its own key into a council.
 */
export async function handleSignCouncilRoster(
  userId: string,
  payload: { councilId: string; chain: RosterVersionWire[]; proposal: RosterVersionWire }
): Promise<{ signature: string }> {
  const { loaded, identitySecret } = await loadWithIdentity(userId);
  const myWire = base64ToUint8(activeIdentity(loaded.state)!.signaturePublicKey);
  const proposal = rosterRecordFromWire(payload.councilId, payload.proposal);

  let previous: RosterRecord | null = null;
  if (payload.chain.length > 0) {
    previous = await verifiedHead(payload.councilId, payload.chain);
    if (proposal.version !== previous.version + 1 || !equal(proposal.previousRosterHash, await rosterHash(previous))) {
      throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The proposal does not follow the council’s current membership.');
    }
  } else if (proposal.version !== 1 || proposal.previousRosterHash.length !== 0) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'A council’s first membership must be version 1.');
  }

  const me = proposal.members.find((m) => m.userId === userId);
  if (me && !equal(me.identityPublicKeyWire, myWire)) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The proposal names you with a key that is not yours.');
  }

  if (previous) {
    const newcomers = proposal.members.filter(
      (m) =>
        m.userId !== userId &&
        !previous!.members.some((p) => p.slot === m.slot && p.userId === m.userId && equal(p.identityPublicKeyWire, m.identityPublicKeyWire))
    );

    if (newcomers.length > 0) {
      const fingerprints = Object.fromEntries(
        await Promise.all(newcomers.map(async (m) => [m.userId, await computeKeyFingerprint(uint8ToBase64(m.identityPublicKeyWire))]))
      );
      const { results } = await handleCheckFingerprints(userId, { userFingerprints: fingerprints }, { record: false });

      if (results.some((r) => r.status !== 'trusted')) {
        throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'Check the identity of every newcomer before signing.');
      }
    }
  }

  return { signature: uint8ToBase64(await signRoster(proposal, identitySecret)) };
}

// Transfer keys of a resharing session, held while the helper works through it.
const sessionTransferKeys = new Map<string, Map<number, Uint8Array>>();

/**
 * One batch of a resharing, helper side: the target custodians' keys checked
 * against the verified chain, then a sub-share of this helper's share of each
 * escrow for each of them. Returns new transfer keys when this vault has none
 * for the session (first batch, or after a reload).
 */
export async function handleCouncilReshareBatch(
  userId: string,
  payload: { batch: CouncilReshareBatch }
): Promise<{ keys: CouncilReshareKeysBody | null; subShares: CouncilReshareSubSharesBody | null }> {
  const { loaded, identitySecret } = await loadWithIdentity(userId);
  const { batch } = payload;
  const target = await verifiedHead(batch.council_id, batch.chain);
  if (target.version !== batch.target_roster_version) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The resharing targets another membership than the council’s current one.');
  }

  const context = {
    sessionId: batch.session_id,
    councilId: batch.council_id,
    target,
    helperSlots: batch.helper_slots,
    mySlot: batch.my_slot,
    identitySecretKey: identitySecret,
  };
  let keys: CouncilReshareKeysBody | null = null;
  let transferKeys = sessionTransferKeys.get(batch.session_id);

  // The server holds none of ours (first batch, or an earlier upload failed), or
  // this vault lost them (reload): new ones, which supersede any sent before.
  if (!transferKeys || !batch.transfer_keys_done) {
    const built = await buildReshareKeys({ ...context, recipientKeys: await membersKeys(userId, target) });
    transferKeys = built.transferKeys;
    keys = built.body;
    sessionTransferKeys.set(batch.session_id, transferKeys);
  }

  if (batch.escrows.length === 0) return { keys, subShares: null };

  const secretKeys = [...loaded.state.encryptionKeys].sort((a, b) => b.version - a.version).map((k) => base64ToUint8(k.secretKey));
  const escrows = [];

  for (const entry of batch.escrows) {
    // A share that does not verify is never reshared: the rest of the council
    // would inherit it.
    let share: Uint8Array;
    try {
      share = await openCustodianShare(entry.capsule, escrowRecordFromWire(entry.user_id, entry.record), {
        userId: entry.user_id,
        councilId: batch.council_id,
        secretKeys,
      });
    } catch (err) {
      throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, (err as Error).message);
    }
    try {
      escrows.push(await buildReshareSubShares(context, transferKeys, entry.escrow_id, share));
    } finally {
      share.fill(0);
    }
  }

  return { keys, subShares: { escrows } };
}
