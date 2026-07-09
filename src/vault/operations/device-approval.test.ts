import { generateUserKeyPair } from '@encryption/src/crypto';
import { exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { deviceKeyDecimalFingerprint, unwrapBootstrapOnNewDevice, wrapBootstrapForNewDevice } from '@encryption/src/vault/operations/device-approval';

describe('device decimal fingerprint', () => {
  it('produces a fixed 40-digit (128-bit, groups-of-5-friendly) decimal string', async () => {
    const ephemeral = await generateUserKeyPair();
    const decimal = await deviceKeyDecimalFingerprint(exportPublicKeyAsBase64(ephemeral.publicKey));

    expect(decimal).toMatch(/^\d{40}$/);
  });

  it('is stable for the same key', async () => {
    const ephemeral = await generateUserKeyPair();
    const key = exportPublicKeyAsBase64(ephemeral.publicKey);

    expect(await deviceKeyDecimalFingerprint(key)).toEqual(await deviceKeyDecimalFingerprint(key));
  });
});

describe('bootstrap (VRK + identity key) forwarding to a new device', () => {
  it('wraps when the decimal fingerprint matches, unwraps both keys on the new device, spaces ignored', async () => {
    const ephemeral = await generateUserKeyPair();
    const devicePublicKeyB64 = exportPublicKeyAsBase64(ephemeral.publicKey);
    const decimal = await deviceKeyDecimalFingerprint(devicePublicKeyB64);
    const spaced = decimal.replace(/(\d{5})(?=\d)/g, '$1 ');
    const vrk = crypto.getRandomValues(new Uint8Array(32));
    const identitySecretKey = crypto.getRandomValues(new Uint8Array(64));

    const wrapped = await wrapBootstrapForNewDevice(vrk, identitySecretKey, devicePublicKeyB64, spaced);
    expect(wrapped).not.toBeNull();

    const unwrapped = await unwrapBootstrapOnNewDevice(wrapped!, ephemeral.secretKey);
    expect(unwrapped.vrk).toEqual(vrk);
    expect(unwrapped.identitySecretKey).toEqual(identitySecretKey);
  });

  it('refuses to wrap when the decimal fingerprint does not match (server swapped the key)', async () => {
    const ephemeral = await generateUserKeyPair();
    const devicePublicKeyB64 = exportPublicKeyAsBase64(ephemeral.publicKey);
    const vrk = crypto.getRandomValues(new Uint8Array(32));
    const identitySecretKey = crypto.getRandomValues(new Uint8Array(64));

    expect(await wrapBootstrapForNewDevice(vrk, identitySecretKey, devicePublicKeyB64, '000000000000000000000000000000000000001')).toBeNull();
  });
});
