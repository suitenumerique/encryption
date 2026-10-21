/**
 * @vitest-environment jsdom
 */
import { describe, expect, it, vi } from 'vitest';

import { VaultClient } from '@encryption/src/client/vault-client';
import { MSG_VAULT_FETCH_PUBLIC_KEYS, MSG_VAULT_GET_PUBLIC_KEY, MSG_VAULT_HAS_KEYS } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

// The auto-verify flow is exercised at the public API boundary (shareKeys /
// encryptWithoutKey) with the low-level vault round-trip and the interface
// overlay both stubbed, so no iframe / DOM is needed. The context / profile
// tests below do touch the DOM, hence the jsdom environment.
interface PendingContext {
  verifyRecipients?: { recipients: Record<string, { email: string; name?: string }> };
  recipientProfile?: { userId: string; label: { email: string; name?: string } };
}

interface Internal {
  vaultRequest: (...args: unknown[]) => Promise<unknown>;
  openVerifyRecipients: (recipients: Record<string, { email: string; name?: string }>) => Promise<'resolved' | 'cancelled'>;
  sendContext: (target: { postMessage: (...args: unknown[]) => void } | null) => void;
  pendingContext: PendingContext | null;
}

function makeClient(): { client: VaultClient; internal: Internal } {
  const client = new VaultClient({
    vaultUrl: 'https://data.encryption.test',
    interfaceUrl: 'https://encryption.test',
  });

  return { client, internal: client as unknown as Internal };
}

const untrusted = () => new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'Refusing to wrap for untrusted or unverified recipients: u1');

describe('VaultClient recipient verification', () => {
  const key = new ArrayBuffer(8);
  const recipients = { u1: { email: 'u1@example.test' } };

  it('opens the verify modal and retries shareKeys once when the user trusts all', async () => {
    const { client, internal } = makeClient();
    const encryptedKeys = { u1: new ArrayBuffer(4) };
    const vaultRequest = vi.fn().mockRejectedValueOnce(untrusted()).mockResolvedValueOnce({ encryptedKeys });
    internal.vaultRequest = vaultRequest;
    const openVerify = vi.spyOn(internal, 'openVerifyRecipients').mockResolvedValue('resolved');
    const fingerprintChanged = vi.fn();
    client.on('fingerprint-changed', fingerprintChanged);

    const result = await client.shareKeys(key, recipients);

    expect(openVerify).toHaveBeenCalledWith(recipients);
    expect(vaultRequest).toHaveBeenCalledTimes(2);
    expect(result).toEqual({ encryptedKeys });
    expect(fingerprintChanged).toHaveBeenCalledTimes(1);
  });

  it('rethrows the original error and does not retry when the user cancels', async () => {
    const { client, internal } = makeClient();
    const original = untrusted();
    const vaultRequest = vi.fn().mockRejectedValue(original);
    internal.vaultRequest = vaultRequest;
    vi.spyOn(internal, 'openVerifyRecipients').mockResolvedValue('cancelled');

    await expect(client.shareKeys(key, recipients)).rejects.toBe(original);
    expect(vaultRequest).toHaveBeenCalledTimes(1);
  });

  it('does not open the modal for a non-trust error', async () => {
    const { client, internal } = makeClient();
    const original = new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'nope');
    internal.vaultRequest = vi.fn().mockRejectedValue(original);
    const openVerify = vi.spyOn(internal, 'openVerifyRecipients');

    await expect(client.shareKeys(key, recipients)).rejects.toBe(original);
    expect(openVerify).not.toHaveBeenCalled();
  });

  it('also guards encryptWithoutKey (retry on resolved)', async () => {
    const { client, internal } = makeClient();
    const encrypted = { encryptedContent: new ArrayBuffer(4), encryptedKeys: { u1: new ArrayBuffer(4) } };
    const vaultRequest = vi.fn().mockRejectedValueOnce(untrusted()).mockResolvedValueOnce(encrypted);
    internal.vaultRequest = vaultRequest;
    const openVerify = vi.spyOn(internal, 'openVerifyRecipients').mockResolvedValue('resolved');

    const result = await client.encryptWithoutKey(new ArrayBuffer(8), recipients);

    expect(openVerify).toHaveBeenCalledWith(recipients);
    expect(vaultRequest).toHaveBeenCalledTimes(2);
    expect(result).toEqual(encrypted);
  });

  it('settles as cancelled when the interface closes before answering', async () => {
    const { client, internal } = makeClient();
    const outcome = internal.openVerifyRecipients(recipients);

    client.closeInterface();

    await expect(outcome).resolves.toBe('cancelled');
  });
});

const INTERFACE_ORIGIN = 'https://encryption.test';

describe('VaultClient per-flow context', () => {
  it('carries the labeled recipients when the verify overlay is open', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });

    // Simulate the verify overlay being open for a labeled map.
    internal.pendingContext = { verifyRecipients: { recipients: { u1: { email: 'alice@example.test', name: 'Alice' } } } };
    const target = { postMessage: vi.fn() };
    internal.sendContext(target);

    expect(target.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        suiteUserId: 'me',
        verifyRecipients: { recipients: { u1: { email: 'alice@example.test', name: 'Alice' } } },
      }),
      INTERFACE_ORIGIN
    );
  });

  it('sends only suiteUserId (no flow block) when no flow is active', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });

    const target = { postMessage: vi.fn() };
    internal.sendContext(target);

    const [payload] = target.postMessage.mock.calls[0];
    expect(payload).not.toHaveProperty('verifyRecipients');
    expect(payload).not.toHaveProperty('recipientProfile');
    expect(payload.suiteUserId).toBe('me');
  });
});

describe('VaultClient.openRecipientProfile', () => {
  it('loads the interface at /recipient-profile in a hidden full-viewport layer on the body', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });

    client.openRecipientProfile('u1', { email: 'alice@example.test' });

    const iframe = document.body.querySelector('iframe[title="Encryption Interface"]');
    expect(iframe).not.toBeNull();
    expect(iframe!.getAttribute('src')).toContain('/recipient-profile');
    // Hidden until the app inside reports it mounted; transparent over the product.
    expect((iframe!.parentElement as HTMLElement).style.visibility).toBe('hidden');
    expect((iframe as HTMLIFrameElement).style.background).toBe('transparent');
    expect(internal.pendingContext).toEqual({ recipientProfile: { userId: 'u1', label: { email: 'alice@example.test' } } });
  });

  it('threads the profile userId and its label into the context payload', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });

    client.openRecipientProfile('u1', { email: 'alice@example.test', name: 'Alice' });

    const target = { postMessage: vi.fn() };
    internal.sendContext(target);

    expect(target.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        recipientProfile: { userId: 'u1', label: { email: 'alice@example.test', name: 'Alice' } },
      }),
      INTERFACE_ORIGIN
    );
  });
});

describe('VaultClient encryption status', () => {
  const identity = new Uint8Array([1, 2, 3, 4]).buffer;
  const otherIdentity = new Uint8Array([5, 6, 7, 8]).buffer;

  // The vault answers by message type: has-keys, fetch-public-keys, get-public-key.
  async function statusWith({ hasKeys, registered, verified = true }: { hasKeys: boolean; registered: ArrayBuffer | null; verified?: boolean }) {
    const { client, internal } = makeClient();
    const registeredFingerprint = registered ? await client.computeKeyFingerprint(registered) : null;

    internal.vaultRequest = vi.fn(async (type: unknown) => {
      if (type === MSG_VAULT_HAS_KEYS) return { hasKeys };
      if (type === MSG_VAULT_FETCH_PUBLIC_KEYS) {
        return { users: registered ? { sub1: { verified, identityFingerprint: registeredFingerprint } } : {} };
      }
      if (type === MSG_VAULT_GET_PUBLIC_KEY) return { publicKey: new ArrayBuffer(4), signaturePublicKey: identity };
      throw new Error(`unexpected ${String(type)}`);
    });
    client.setAuthContext({ suiteUserId: 'sub1' });

    return client.getEncryptionStatus();
  }

  it('is active when this device holds the identity registered for the account', async () => {
    await expect(statusWith({ hasKeys: true, registered: identity })).resolves.toEqual({ state: 'active', registered: true });
  });

  it('needs attention when this device holds another identity than the registered one', async () => {
    await expect(statusWith({ hasKeys: true, registered: otherIdentity })).resolves.toEqual({ state: 'needs-attention', registered: true });
  });

  it('needs attention when the registered record fails its binding check, even for the same identity', async () => {
    await expect(statusWith({ hasKeys: true, registered: identity, verified: false })).resolves.toEqual({
      state: 'needs-attention',
      registered: true,
    });
  });

  it('is disabled for the account when this device holds keys the account no longer registers', async () => {
    await expect(statusWith({ hasKeys: true, registered: null })).resolves.toEqual({ state: 'disabled-for-account', registered: false });
  });

  it('is not set up on a device without keys, telling whether the account has encryption elsewhere', async () => {
    await expect(statusWith({ hasKeys: false, registered: identity })).resolves.toEqual({ state: 'not-set-up', registered: true });
    await expect(statusWith({ hasKeys: false, registered: null })).resolves.toEqual({ state: 'not-set-up', registered: false });
  });

  it('needs the auth context', async () => {
    const { client } = makeClient();

    await expect(client.getEncryptionStatus()).rejects.toMatchObject({ code: VaultErrorCode.NOT_INITIALIZED });
  });
});

describe('VaultClient settings sections', () => {
  it('opens the home without a section and a single flow with one', () => {
    // Overlays left open by the tests above.
    document.body.replaceChildren();
    const { client } = makeClient();

    client.openSettings();
    expect(document.querySelector('iframe')?.src).toMatch(/^https:\/\/encryption\.test\/settings#/);

    client.openSettings('trusted-contacts');
    expect(document.querySelectorAll('iframe')).toHaveLength(1);
    expect(document.querySelector('iframe')?.src).toMatch(/^https:\/\/encryption\.test\/settings\/trusted-contacts#/);

    client.closeInterface();
  });

  it('refuses an unknown section', () => {
    const { client } = makeClient();

    expect(() => client.openSettings('nope' as never)).toThrow(/Unknown settings section/);
  });
});
