/**
 * Sealing the vault state for the server, and verifying it on the way back.
 *
 * Each item's payload is sealed with the VRK (XChaCha20-Poly1305) and the whole
 * set is pinned by a manifest signed with the identity key. `sealState` /
 * `openState` are the round trip; `buildSignedManifest` produces what the server
 * stores; `verifyPulledVault` runs every check a device must pass before trusting
 * a pull: the signature (against the identity it already trusts), full coverage
 * of the received items, and no revision rollback.
 */
import { decryptContent, encryptContent } from '@encryption/src/crypto/encryption';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { SignaturePublicKey, SignatureSecretKey } from '@encryption/src/crypto/signature';
import { type PlainItem, itemsToState, plainItemSchema, stateToItems } from '@encryption/src/crypto/vault-items';
import {
  type SealedItem,
  buildManifest,
  isRollback,
  parseManifest,
  sealedItemsMatchManifest,
  signManifest,
  verifyManifest,
} from '@encryption/src/crypto/vault-manifest';
import type { VaultState } from '@encryption/src/crypto/vault-state';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export async function sealItem(item: PlainItem, vrk: Uint8Array): Promise<SealedItem> {
  const ciphertext = await encryptContent(encoder.encode(JSON.stringify(item.payload)), vrk);

  return { id: item.id, type: item.type, revisionDate: item.revisionDate, ciphertext: uint8ToBase64(ciphertext) };
}

export async function openItem(sealed: SealedItem, vrk: Uint8Array): Promise<PlainItem> {
  const payload = JSON.parse(decoder.decode(await decryptContent(base64ToUint8(sealed.ciphertext), vrk)));

  // Validate the decrypted shape against the item's declared type: authenticity
  // is proven by the manifest signature, this catches a payload that doesn't
  // match today's schema (a drifted or corrupted item) instead of letting an
  // undefined field propagate into VaultState.
  return plainItemSchema.parse({ id: sealed.id, type: sealed.type, revisionDate: sealed.revisionDate, payload });
}

export async function sealState(state: VaultState, vrk: Uint8Array): Promise<SealedItem[]> {
  return Promise.all(stateToItems(state).map((item) => sealItem(item, vrk)));
}

export async function openState(sealed: SealedItem[], vrk: Uint8Array): Promise<VaultState> {
  return itemsToState(await Promise.all(sealed.map((s) => openItem(s, vrk))));
}

export async function buildSignedManifest(
  revision: number,
  identityGen: number,
  sealed: SealedItem[],
  identitySecretKey: SignatureSecretKey
): Promise<{ manifest: string; manifestSig: string }> {
  const manifest = buildManifest(revision, identityGen, sealed);

  return { manifest: JSON.stringify(manifest), manifestSig: await signManifest(manifest, identitySecretKey) };
}

/**
 * Fails closed: any parse error, malformed input, bad signature, coverage gap,
 * or rollback returns false. Everything here runs on server-supplied data, so a
 * throw (e.g. garbage base64 in the signature) must be treated as "reject", never
 * allowed to crash the caller.
 */
export async function verifyPulledVault(
  sealed: SealedItem[],
  manifestJson: string,
  manifestSig: string,
  trustedIdentityPublicKey: SignaturePublicKey,
  lastSeenRevision: number
): Promise<boolean> {
  try {
    const manifest = parseManifest(manifestJson);
    if (!manifest) return false;

    if (isRollback(manifest.revision, lastSeenRevision)) return false;
    if (!(await verifyManifest(manifest, manifestSig, trustedIdentityPublicKey))) return false;

    return sealedItemsMatchManifest(sealed, manifest);
  } catch {
    return false;
  }
}
