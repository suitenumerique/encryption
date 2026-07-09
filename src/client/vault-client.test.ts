/**
 * @jest-environment jsdom
 */
import { VaultClient } from '@encryption/src/client/vault-client';
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
    const vaultRequest = jest.fn().mockRejectedValueOnce(untrusted()).mockResolvedValueOnce({ encryptedKeys });
    internal.vaultRequest = vaultRequest;
    const openVerify = jest.spyOn(internal, 'openVerifyRecipients').mockResolvedValue('resolved');
    const fingerprintChanged = jest.fn();
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
    const vaultRequest = jest.fn().mockRejectedValue(original);
    internal.vaultRequest = vaultRequest;
    jest.spyOn(internal, 'openVerifyRecipients').mockResolvedValue('cancelled');

    await expect(client.shareKeys(key, recipients)).rejects.toBe(original);
    expect(vaultRequest).toHaveBeenCalledTimes(1);
  });

  it('does not open the modal for a non-trust error', async () => {
    const { client, internal } = makeClient();
    const original = new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'nope');
    internal.vaultRequest = jest.fn().mockRejectedValue(original);
    const openVerify = jest.spyOn(internal, 'openVerifyRecipients');

    await expect(client.shareKeys(key, recipients)).rejects.toBe(original);
    expect(openVerify).not.toHaveBeenCalled();
  });

  it('also guards encryptWithoutKey (retry on resolved)', async () => {
    const { client, internal } = makeClient();
    const encrypted = { encryptedContent: new ArrayBuffer(4), encryptedKeys: { u1: new ArrayBuffer(4) } };
    const vaultRequest = jest.fn().mockRejectedValueOnce(untrusted()).mockResolvedValueOnce(encrypted);
    internal.vaultRequest = vaultRequest;
    const openVerify = jest.spyOn(internal, 'openVerifyRecipients').mockResolvedValue('resolved');

    const result = await client.encryptWithoutKey(new ArrayBuffer(8), recipients);

    expect(openVerify).toHaveBeenCalledWith(recipients);
    expect(vaultRequest).toHaveBeenCalledTimes(2);
    expect(result).toEqual(encrypted);
  });
});

const INTERFACE_ORIGIN = 'https://encryption.test';

describe('VaultClient per-flow context', () => {
  it('carries the labeled recipients when the verify overlay is open', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });

    // Simulate the verify overlay being open for a labeled map.
    internal.pendingContext = { verifyRecipients: { recipients: { u1: { email: 'alice@example.test', name: 'Alice' } } } };
    const target = { postMessage: jest.fn() };
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

    const target = { postMessage: jest.fn() };
    internal.sendContext(target);

    const [payload] = target.postMessage.mock.calls[0];
    expect(payload).not.toHaveProperty('verifyRecipients');
    expect(payload).not.toHaveProperty('recipientProfile');
    expect(payload.suiteUserId).toBe('me');
  });
});

describe('VaultClient.openRecipientProfile', () => {
  it('mounts the interface at /recipient-profile in the given container', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });
    const container = document.createElement('div');
    document.body.appendChild(container);

    client.openRecipientProfile(container, 'u1', { email: 'alice@example.test' });

    const iframe = container.querySelector('iframe');
    expect(iframe).not.toBeNull();
    expect(iframe!.src).toContain('/recipient-profile');
    expect(internal.pendingContext).toEqual({ recipientProfile: { userId: 'u1', label: { email: 'alice@example.test' } } });
  });

  it('threads the profile userId and its label into the context payload', () => {
    const { client, internal } = makeClient();
    client.setAuthContext({ suiteUserId: 'me' });
    const container = document.createElement('div');
    document.body.appendChild(container);

    client.openRecipientProfile(container, 'u1', { email: 'alice@example.test', name: 'Alice' });

    const target = { postMessage: jest.fn() };
    internal.sendContext(target);

    expect(target.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        recipientProfile: { userId: 'u1', label: { email: 'alice@example.test', name: 'Alice' } },
      }),
      INTERFACE_ORIGIN
    );
  });
});
