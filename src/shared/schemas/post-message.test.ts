import { describe, expect, it } from 'vitest';

import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_COUNCIL_CREATE_ESCROW,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_SHARE_KEYS,
} from '@encryption/src/shared/constants';
import { PRIVILEGED_OPERATIONS, VAULT_REQUEST_PAYLOADS, parseVaultRequest } from '@encryption/src/shared/schemas/post-message';

const refusal = (type: string, payload: unknown) => {
  const parsed = parseVaultRequest(type, payload);

  return 'error' in parsed ? parsed.error : null;
};

describe('parseVaultRequest', () => {
  it('accepts an operation without payload', () => {
    expect(parseVaultRequest(MSG_VAULT_HAS_KEYS, undefined)).toEqual({ request: { type: MSG_VAULT_HAS_KEYS, payload: {} } });
  });

  it('refuses an unknown operation', () => {
    expect(refusal('vault:unknown', {})).toBe('Unknown operation.');
    expect(refusal('__proto__', {})).toBe('Unknown operation.');
  });

  it('takes binary content as is, without copying it', () => {
    const data = new ArrayBuffer(8);
    const parsed = parseVaultRequest(MSG_VAULT_ENCRYPT_WITHOUT_KEY, { data, recipientSubs: ['sub-1'] });

    expect('request' in parsed && parsed.request.payload).toEqual({ data, recipientSubs: ['sub-1'] });
    expect('request' in parsed && (parsed.request.payload as { data: ArrayBuffer }).data).toBe(data);
  });

  it('accepts a byte view for a binary field, as an ArrayBuffer of exactly its bytes', () => {
    const view = new Uint8Array([0, 1, 2, 3]).subarray(1, 3);
    const parsed = parseVaultRequest(MSG_VAULT_ENCRYPT_WITHOUT_KEY, { data: view, recipientSubs: [] });
    const data = 'request' in parsed ? (parsed.request.payload as { data: ArrayBuffer }).data : null;

    expect(data).toBeInstanceOf(ArrayBuffer);
    expect([...new Uint8Array(data!)]).toEqual([1, 2]);
  });

  it('refuses a share or an encryption without its recipients, rather than sharing with nobody', () => {
    expect(refusal(MSG_VAULT_ENCRYPT_WITHOUT_KEY, { data: new ArrayBuffer(1) })).toContain('recipientSubs');
    expect(refusal(MSG_VAULT_SHARE_KEYS, { encryptedSymmetricKey: new ArrayBuffer(1), userPublicKeys: {} })).toContain('recipientSubs');
  });

  it('names the malformed fields, never their values', () => {
    const error = refusal(MSG_VAULT_DECRYPT_WITH_KEY, { encryptedData: 'secret-content', encryptedSymmetricKey: new ArrayBuffer(1), keyVersion: 1 });

    expect(error).toContain('encryptedData');
    expect(error).not.toContain('secret-content');
  });

  it('refuses a trust decision that names no target', () => {
    expect(refusal(MSG_VAULT_ACCEPT_FINGERPRINT, { fingerprint: '1234' })).not.toBeNull();
    expect(refusal(MSG_VAULT_ACCEPT_FINGERPRINT, { sub: 'sub-1', fingerprint: '1234' })).toBeNull();
  });

  it("checks a council message's own fields, leaving what came from the server to its handler", () => {
    expect(refusal(MSG_VAULT_COUNCIL_CREATE_ESCROW, { councilId: '', chain: [] })).toContain('councilId');
    expect(refusal(MSG_VAULT_COUNCIL_CREATE_ESCROW, { councilId: 'c', chain: 'x', lang: 'klingon' })).toContain('chain');
    expect(refusal(MSG_VAULT_COUNCIL_CREATE_ESCROW, { councilId: 'c', chain: [{ anything: true }] })).toBeNull();
  });

  it('refuses a record where a map of fingerprints is expected', () => {
    expect(refusal(MSG_VAULT_CHECK_FINGERPRINTS, { userFingerprints: ['1234'] })).toContain('userFingerprints');
  });
});

describe('PRIVILEGED_OPERATIONS', () => {
  it('names only operations the vault knows', () => {
    for (const type of PRIVILEGED_OPERATIONS) expect(Object.hasOwn(VAULT_REQUEST_PAYLOADS, type), type).toBe(true);
  });

  it('leaves the product operations open', () => {
    for (const type of [
      MSG_VAULT_HAS_KEYS,
      MSG_VAULT_ENCRYPT_WITHOUT_KEY,
      MSG_VAULT_DECRYPT_WITH_KEY,
      MSG_VAULT_SHARE_KEYS,
      MSG_VAULT_CHECK_FINGERPRINTS,
    ]) {
      expect(PRIVILEGED_OPERATIONS.has(type), type).toBe(false);
    }
  });
});
