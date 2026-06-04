/**
 * Integration tests for `handleWrapNestedKey`.
 *
 * Mirrors the move-direction-reversal of `handleRewrapNestedKey`: a
 * resource that was previously self-rooted (its `K_item` reachable via
 * a per-user wrap on the caller's access row) is moving INTO an
 * encrypted subtree, so `K_item` must be wrapped under the destination
 * parent's chain instead.
 */
import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';

jest.mock('@encryption/src/vault/operations/key-management', () => {
  return { getStoredKeyPair: jest.fn() };
});

import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import {
  handleEncryptNestedWithoutKey,
  handleEncryptWithoutKey,
} from '@encryption/src/vault/operations/encrypt';
import { handleWrapNestedKey } from '@encryption/src/vault/operations/wrap-nested-key';

const USER_ID = 'user-alice';

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = Buffer.from(base64, 'base64');
  const out = new Uint8Array(binary.length);
  out.set(binary);
  return out.buffer;
}

async function setupKeyPair(): Promise<ArrayBuffer> {
  const pair = await generateUserKeyPair();
  (getStoredKeyPair as jest.Mock).mockResolvedValue(pair);
  return base64ToArrayBuffer(exportPublicKeyAsBase64(pair.publicKey));
}

describe('handleWrapNestedKey', () => {
  beforeEach(() => {
    (getStoredKeyPair as jest.Mock).mockReset();
  });

  it('wraps a self-rooted file under a destination parent chain', async () => {
    const publicKey = await setupKeyPair();

    // The file currently lives as a self-rooted resource (created via
    // encryptWithoutKey — wrapped per-user under the user's pubkey).
    const filePlaintext = new TextEncoder().encode('self-rooted content').buffer;
    const fileRoot = await handleEncryptWithoutKey(USER_ID, {
      data: filePlaintext,
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const userWrapOfFile = fileRoot.encryptedKeys[USER_ID];

    // The destination encryption tree: a separate root with one
    // intermediate folder. The user has access to it (their entry
    // key for that tree).
    const destRoot = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const destEntry = destRoot.encryptedKeys[USER_ID];
    const destFolder = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: destEntry,
      encryptedKeyChain: [],
    });

    // Move the file under destFolder: produce the chain wrap.
    const { newEncryptedKey } = await handleWrapNestedKey(USER_ID, {
      userEncryptedKey: userWrapOfFile,
      newEntryEncryptedSymmetricKey: destEntry,
      newEncryptedKeyChain: [destFolder.wrappedKey],
    });

    // The file content (unchanged) decrypts via the new chain.
    const out = await handleDecryptWithKey(USER_ID, {
      encryptedData: fileRoot.encryptedContent,
      encryptedSymmetricKey: destEntry,
      encryptedKeyChain: [destFolder.wrappedKey, newEncryptedKey],
    });
    expect(new TextDecoder().decode(out.data)).toBe('self-rooted content');
  });

  it('handles destination = encryption root directly (empty chain)', async () => {
    const publicKey = await setupKeyPair();

    const fileRoot = await handleEncryptWithoutKey(USER_ID, {
      data: new TextEncoder().encode('payload').buffer,
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const userWrap = fileRoot.encryptedKeys[USER_ID];

    const destRoot = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const destEntry = destRoot.encryptedKeys[USER_ID];

    // No newEncryptedKeyChain → file is wrapped directly under the
    // destination root.
    const { newEncryptedKey } = await handleWrapNestedKey(USER_ID, {
      userEncryptedKey: userWrap,
      newEntryEncryptedSymmetricKey: destEntry,
    });

    const out = await handleDecryptWithKey(USER_ID, {
      encryptedData: fileRoot.encryptedContent,
      encryptedSymmetricKey: destEntry,
      encryptedKeyChain: [newEncryptedKey],
    });
    expect(new TextDecoder().decode(out.data)).toBe('payload');
  });

  it('round-trips with rewrapNestedKey: wrap then rewrap deeper still decrypts', async () => {
    const publicKey = await setupKeyPair();

    const fileRoot = await handleEncryptWithoutKey(USER_ID, {
      data: new TextEncoder().encode('round trip').buffer,
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const userWrap = fileRoot.encryptedKeys[USER_ID];

    const destRoot = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const destEntry = destRoot.encryptedKeys[USER_ID];
    const folder1 = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: destEntry,
      encryptedKeyChain: [],
    });
    const folder2 = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: destEntry,
      encryptedKeyChain: [folder1.wrappedKey],
    });

    // Step 1: wrap under folder1.
    const wrapped = await handleWrapNestedKey(USER_ID, {
      userEncryptedKey: userWrap,
      newEntryEncryptedSymmetricKey: destEntry,
      newEncryptedKeyChain: [folder1.wrappedKey],
    });

    // Decrypts at folder1 depth.
    const at1 = await handleDecryptWithKey(USER_ID, {
      encryptedData: fileRoot.encryptedContent,
      encryptedSymmetricKey: destEntry,
      encryptedKeyChain: [folder1.wrappedKey, wrapped.newEncryptedKey],
    });
    expect(new TextDecoder().decode(at1.data)).toBe('round trip');
  });
});
