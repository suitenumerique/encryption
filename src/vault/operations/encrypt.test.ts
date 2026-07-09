/**
 * Integration tests for the vault encrypt/decrypt handlers.
 *
 * Covers the three "create or use" operations and verifies that each round-
 * trips through handleDecryptWithKey:
 *   - handleEncryptWithoutKey (root creation, wraps K_new for each user)
 *   - handleEncryptNestedWithoutKey (nested creation, wraps K_new under parent)
 *   - handleEncryptWithKey (symmetric use of an existing key, flat + chain)
 *
 * The handlers normally read the user's key pair from IndexedDB. Since
 * IndexedDB isn't available in the Jest node environment, we stub the
 * key-management module to return a freshly-generated pair.
 */
import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import { handleEncryptNestedWithoutKey, handleEncryptWithKey, handleEncryptWithoutKey } from '@encryption/src/vault/operations/encrypt';
import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';

// Mock BEFORE importing the handlers (Jest hoists jest.mock to the top of the file).
jest.mock('@encryption/src/vault/operations/key-management', () => {
  return { getStoredKeyPair: jest.fn() };
});

const USER_ID = 'user-alice';

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = Buffer.from(base64, 'base64');
  // Copy into a dedicated ArrayBuffer to avoid any slice/offset confusion.
  const out = new Uint8Array(binary.length);
  out.set(binary);
  return out.buffer;
}

async function setupKeyPair(): Promise<ArrayBuffer> {
  const pair = await generateUserKeyPair();
  (getStoredKeyPair as jest.Mock).mockResolvedValue(pair);
  return base64ToArrayBuffer(exportPublicKeyAsBase64(pair.publicKey));
}

function asBuffer(view: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (view instanceof ArrayBuffer) {
    return view;
  }
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}

describe('vault encrypt operations', () => {
  beforeEach(() => {
    (getStoredKeyPair as jest.Mock).mockReset();
  });

  describe('handleEncryptWithoutKey (root)', () => {
    it('round-trips content: encrypt root, then decrypt with the wrapped entry key', async () => {
      const publicKey = await setupKeyPair();
      const plaintext = new TextEncoder().encode('root file content').buffer;

      const { encryptedContent, encryptedKeys } = await handleEncryptWithoutKey(USER_ID, {
        data: plaintext,
        userPublicKeys: { [USER_ID]: publicKey },
      });

      expect(encryptedKeys[USER_ID]).toBeDefined();

      const { data } = await handleDecryptWithKey(USER_ID, {
        encryptedData: encryptedContent,
        encryptedSymmetricKey: encryptedKeys[USER_ID],
      });

      expect(new TextDecoder().decode(data)).toBe('root file content');
    });

    it('rejects when no key pair is stored', async () => {
      (getStoredKeyPair as jest.Mock).mockResolvedValue(null);

      await expect(
        handleEncryptWithoutKey(USER_ID, {
          data: new ArrayBuffer(4),
          userPublicKeys: {},
        })
      ).rejects.toThrow('No key pair found');
    });
  });

  describe('handleEncryptNestedWithoutKey', () => {
    it('round-trips a nested resource with entry + empty chain (direct parent)', async () => {
      const publicKey = await setupKeyPair();
      const parentPlaintext = new ArrayBuffer(0); // parent folder: empty payload

      const { encryptedKeys: parentWraps } = await handleEncryptWithoutKey(USER_ID, {
        data: parentPlaintext,
        userPublicKeys: { [USER_ID]: publicKey },
      });
      const entry = parentWraps[USER_ID];

      const childPlaintext = new TextEncoder().encode('child file').buffer;

      const { encryptedContent, wrappedKey } = await handleEncryptNestedWithoutKey(USER_ID, {
        data: childPlaintext,
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [],
      });

      // The recipient resolves entry + [wrappedKey] to get K_child and decrypts.
      const { data } = await handleDecryptWithKey(USER_ID, {
        encryptedData: encryptedContent,
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [wrappedKey],
      });

      expect(new TextDecoder().decode(data)).toBe('child file');
    });

    it('round-trips a nested resource through a multi-level chain', async () => {
      const publicKey = await setupKeyPair();

      // Build hierarchy: root -> sub1 -> sub2 -> file.
      const { encryptedKeys: rootWraps } = await handleEncryptWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        userPublicKeys: { [USER_ID]: publicKey },
      });
      const entry = rootWraps[USER_ID];

      const sub1 = await handleEncryptNestedWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [],
      });

      const sub2 = await handleEncryptNestedWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [sub1.wrappedKey],
      });

      const filePlaintext = new TextEncoder().encode('deep file').buffer;
      const file = await handleEncryptNestedWithoutKey(USER_ID, {
        data: filePlaintext,
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [sub1.wrappedKey, sub2.wrappedKey],
      });

      const { data } = await handleDecryptWithKey(USER_ID, {
        encryptedData: file.encryptedContent,
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [sub1.wrappedKey, sub2.wrappedKey, file.wrappedKey],
      });

      expect(new TextDecoder().decode(data)).toBe('deep file');
    });
  });

  describe('handleEncryptWithKey (symmetric, no mint)', () => {
    it('round-trips with flat entry (no chain) — mirrors Docs', async () => {
      const publicKey = await setupKeyPair();

      const { encryptedKeys } = await handleEncryptWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        userPublicKeys: { [USER_ID]: publicKey },
      });
      const entry = encryptedKeys[USER_ID];

      const plaintext = new TextEncoder().encode('flat payload').buffer;
      const { encryptedData } = await handleEncryptWithKey(USER_ID, {
        data: plaintext,
        encryptedSymmetricKey: entry,
      });

      const { data } = await handleDecryptWithKey(USER_ID, {
        encryptedData,
        encryptedSymmetricKey: entry,
      });

      expect(new TextDecoder().decode(data)).toBe('flat payload');
    });

    it('round-trips with entry + chain — this is the relay scenario that was broken', async () => {
      const publicKey = await setupKeyPair();

      const { encryptedKeys } = await handleEncryptWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        userPublicKeys: { [USER_ID]: publicKey },
      });
      const entry = encryptedKeys[USER_ID];

      // Create a nested file that "lives" at the end of a chain.
      const sub = await handleEncryptNestedWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [],
      });
      const file = await handleEncryptNestedWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        encryptedSymmetricKey: entry,
        encryptedKeyChain: [sub.wrappedKey],
      });
      const fileChain = [sub.wrappedKey, file.wrappedKey];

      // Sender encrypts a relay message using the file's resolved K_file.
      const msg = new TextEncoder().encode('collaborative OT patch').buffer;
      const { encryptedData } = await handleEncryptWithKey(USER_ID, {
        data: msg,
        encryptedSymmetricKey: entry,
        encryptedKeyChain: fileChain,
      });

      // Receiver resolves the same chain → same K_file → decrypts cleanly.
      const { data } = await handleDecryptWithKey(USER_ID, {
        encryptedData,
        encryptedSymmetricKey: entry,
        encryptedKeyChain: fileChain,
      });

      expect(new TextDecoder().decode(data)).toBe('collaborative OT patch');
    });

    it('produces different ciphertexts for the same payload on repeated calls', async () => {
      const publicKey = await setupKeyPair();

      const { encryptedKeys } = await handleEncryptWithoutKey(USER_ID, {
        data: new ArrayBuffer(0),
        userPublicKeys: { [USER_ID]: publicKey },
      });
      const entry = encryptedKeys[USER_ID];

      const payload = new TextEncoder().encode('dup').buffer;
      const a = await handleEncryptWithKey(USER_ID, {
        data: payload.slice(0),
        encryptedSymmetricKey: asBuffer(new Uint8Array(entry)),
      });
      const b = await handleEncryptWithKey(USER_ID, {
        data: payload.slice(0),
        encryptedSymmetricKey: asBuffer(new Uint8Array(entry)),
      });

      const aBytes = new Uint8Array(a.encryptedData);
      const bBytes = new Uint8Array(b.encryptedData);
      expect(aBytes).not.toEqual(bBytes);
    });
  });
});
