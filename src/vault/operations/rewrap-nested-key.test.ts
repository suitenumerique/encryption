/**
 * Integration tests for `handleRewrapNestedKey`.
 *
 * Models the Drive scenario the operation is built for: an encrypted
 * file lives inside a deep folder hierarchy, the user moves it to a
 * different parent within the SAME encryption root, and the file's
 * `K_file` wrapping needs to follow the new parent — without
 * re-encrypting the file content.
 *
 * Each test builds a small encrypted hierarchy via
 * `handleEncryptWithoutKey` (root) + `handleEncryptNestedWithoutKey`
 * (folders + the file), then asks `handleRewrapNestedKey` to produce a
 * new wrap, then verifies that the file content can still be decrypted
 * through the NEW chain — and (crucially) that the OLD chain still
 * decrypts the same bytes (we did not re-encrypt content; only the
 * wrapping changed).
 */
import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import { handleEncryptNestedWithoutKey, handleEncryptWithoutKey } from '@encryption/src/vault/operations/encrypt';
import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';
import { handleRewrapNestedKey } from '@encryption/src/vault/operations/rewrap-nested-key';

jest.mock('@encryption/src/vault/operations/key-management', () => {
  return { getStoredKeyPair: jest.fn() };
});

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

describe('handleRewrapNestedKey', () => {
  beforeEach(() => {
    (getStoredKeyPair as jest.Mock).mockReset();
  });

  it('moves a deep file under a sibling: file content stays decryptable through the new chain', async () => {
    const publicKey = await setupKeyPair();

    // Build hierarchy: root → A → A1 → file
    //                       └ B (sibling, where the file will move)
    const { encryptedKeys: rootWraps } = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const entry = rootWraps[USER_ID];

    const folderA = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });
    const folderA1 = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey],
    });
    const folderB = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });

    // The file lives under A1 — chain entry → A → A1 → file.
    const filePlaintext = new TextEncoder().encode('private notes').buffer;
    const file = await handleEncryptNestedWithoutKey(USER_ID, {
      data: filePlaintext,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey, folderA1.wrappedKey],
    });

    // Sanity: the file decrypts through the OLD chain.
    const before = await handleDecryptWithKey(USER_ID, {
      encryptedData: file.encryptedContent,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey, folderA1.wrappedKey, file.wrappedKey],
    });
    expect(new TextDecoder().decode(before.data)).toBe('private notes');

    // Move the file: parent A1 → parent B. Wrap must follow.
    const { newEncryptedKey } = await handleRewrapNestedKey(USER_ID, {
      encryptedSymmetricKey: entry,
      oldEncryptedKey: file.wrappedKey,
      oldEncryptedKeyChain: [folderA.wrappedKey, folderA1.wrappedKey],
      newEncryptedKeyChain: [folderB.wrappedKey],
    });

    // The new wrap must NOT equal the old one — it's a different
    // ciphertext (different parent key, different nonce).
    expect(new Uint8Array(newEncryptedKey)).not.toEqual(new Uint8Array(file.wrappedKey));

    // The file decrypts through the NEW chain.
    const after = await handleDecryptWithKey(USER_ID, {
      encryptedData: file.encryptedContent,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderB.wrappedKey, newEncryptedKey],
    });
    expect(new TextDecoder().decode(after.data)).toBe('private notes');

    // And the OLD chain still works: we did NOT re-encrypt content,
    // only changed the wrapping layer over K_file.
    const stillOld = await handleDecryptWithKey(USER_ID, {
      encryptedData: file.encryptedContent,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey, folderA1.wrappedKey, file.wrappedKey],
    });
    expect(new TextDecoder().decode(stillOld.data)).toBe('private notes');
  });

  it('handles moves where the OLD parent IS the encryption root (empty old chain)', async () => {
    const publicKey = await setupKeyPair();

    const { encryptedKeys: rootWraps } = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const entry = rootWraps[USER_ID];

    const folderB = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });

    // File initially lives DIRECTLY under root.
    const filePlaintext = new TextEncoder().encode('content').buffer;
    const file = await handleEncryptNestedWithoutKey(USER_ID, {
      data: filePlaintext,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });

    // Move it down one level into folderB.
    const { newEncryptedKey } = await handleRewrapNestedKey(USER_ID, {
      encryptedSymmetricKey: entry,
      oldEncryptedKey: file.wrappedKey,
      // Old chain omitted — old parent IS the root.
      newEncryptedKeyChain: [folderB.wrappedKey],
    });

    const after = await handleDecryptWithKey(USER_ID, {
      encryptedData: file.encryptedContent,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderB.wrappedKey, newEncryptedKey],
    });
    expect(new TextDecoder().decode(after.data)).toBe('content');
  });

  it('handles moves where the NEW parent IS the encryption root (empty new chain)', async () => {
    const publicKey = await setupKeyPair();

    const { encryptedKeys: rootWraps } = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const entry = rootWraps[USER_ID];

    const folderA = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });

    // File lives one level deep, under folderA.
    const filePlaintext = new TextEncoder().encode('content').buffer;
    const file = await handleEncryptNestedWithoutKey(USER_ID, {
      data: filePlaintext,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey],
    });

    // Move it up to root.
    const { newEncryptedKey } = await handleRewrapNestedKey(USER_ID, {
      encryptedSymmetricKey: entry,
      oldEncryptedKey: file.wrappedKey,
      oldEncryptedKeyChain: [folderA.wrappedKey],
      // New chain omitted — new parent IS the root.
    });

    const after = await handleDecryptWithKey(USER_ID, {
      encryptedData: file.encryptedContent,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [newEncryptedKey],
    });
    expect(new TextDecoder().decode(after.data)).toBe('content');
  });

  it('a re-wrap is itself reversible: re-wrap back to the original parent recovers the file', async () => {
    const publicKey = await setupKeyPair();

    const { encryptedKeys: rootWraps } = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const entry = rootWraps[USER_ID];

    const folderA = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });
    const folderB = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });

    const filePlaintext = new TextEncoder().encode('round-trip').buffer;
    const file = await handleEncryptNestedWithoutKey(USER_ID, {
      data: filePlaintext,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey],
    });

    // A → B
    const ab = await handleRewrapNestedKey(USER_ID, {
      encryptedSymmetricKey: entry,
      oldEncryptedKey: file.wrappedKey,
      oldEncryptedKeyChain: [folderA.wrappedKey],
      newEncryptedKeyChain: [folderB.wrappedKey],
    });

    // B → A again
    const ba = await handleRewrapNestedKey(USER_ID, {
      encryptedSymmetricKey: entry,
      oldEncryptedKey: ab.newEncryptedKey,
      oldEncryptedKeyChain: [folderB.wrappedKey],
      newEncryptedKeyChain: [folderA.wrappedKey],
    });

    const back = await handleDecryptWithKey(USER_ID, {
      encryptedData: file.encryptedContent,
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey, ba.newEncryptedKey],
    });
    expect(new TextDecoder().decode(back.data)).toBe('round-trip');
  });

  it('rejects when the OLD chain does not actually unwrap to the file key (wrong parent)', async () => {
    const publicKey = await setupKeyPair();

    const { encryptedKeys: rootWraps } = await handleEncryptWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      userPublicKeys: { [USER_ID]: publicKey },
    });
    const entry = rootWraps[USER_ID];

    const folderA = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });
    const folderB = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [],
    });

    // File belongs under A, but we lie and tell rewrap that B was the
    // old parent. The unwrap of K_file under K_B should fail with
    // libsodium's "wrong secret key" → mapped to WRONG_SECRET_KEY.
    const file = await handleEncryptNestedWithoutKey(USER_ID, {
      data: new ArrayBuffer(0),
      encryptedSymmetricKey: entry,
      encryptedKeyChain: [folderA.wrappedKey],
    });

    await expect(
      handleRewrapNestedKey(USER_ID, {
        encryptedSymmetricKey: entry,
        oldEncryptedKey: file.wrappedKey,
        oldEncryptedKeyChain: [folderB.wrappedKey],
        newEncryptedKeyChain: [folderA.wrappedKey],
      })
    ).rejects.toThrow(/wrong secret key/i);
  });
});
