import { generateDeviceKey, unwrapVrkForDevice, wrapVrkForDevice } from '@encryption/src/crypto/device-cache';

describe('device-key VRK cache', () => {
  it('round-trips the VRK under the device key', async () => {
    const deviceKey = await generateDeviceKey();
    const vrk = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapVrkForDevice(vrk, deviceKey);

    expect(wrapped).not.toEqual(vrk);
    expect(await unwrapVrkForDevice(wrapped, deviceKey)).toEqual(vrk);
  });

  it('produces a non-extractable device key whose bytes cannot be read back', async () => {
    const deviceKey = await generateDeviceKey();

    expect(deviceKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', deviceKey)).rejects.toBeDefined();
  });

  it('cannot be unwrapped by a different device key', async () => {
    const wrapped = await wrapVrkForDevice(crypto.getRandomValues(new Uint8Array(32)), await generateDeviceKey());

    await expect(unwrapVrkForDevice(wrapped, await generateDeviceKey())).rejects.toBeDefined();
  });
});
