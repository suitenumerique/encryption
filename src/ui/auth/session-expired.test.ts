import { describe, expect, it, vi } from 'vitest';

import { ApiError } from '@encryption/src/ui/api/client';
import { SessionExpiredError, StepUpRequiredError, withFreshIdToken } from '@encryption/src/ui/auth/session-expired';

describe('withFreshIdToken', () => {
  it('runs the call with the live ID token', async () => {
    const call = vi.fn().mockResolvedValue('done');

    expect(await withFreshIdToken(async () => 'the-id-token', call)).toBe('done');
    expect(call).toHaveBeenCalledWith('the-id-token');
  });

  it('throws SessionExpiredError, without calling, when there is no live ID token', async () => {
    const call = vi.fn();

    await expect(withFreshIdToken(async () => null, call)).rejects.toBeInstanceOf(SessionExpiredError);
    expect(call).not.toHaveBeenCalled();
  });

  it('turns the server no longer accepting the ID token (401 unauthorized) into SessionExpiredError', async () => {
    const call = vi.fn().mockRejectedValue(new ApiError(401, 'unauthorized'));

    await expect(withFreshIdToken(async () => 'rejected-id-token', call)).rejects.toBeInstanceOf(SessionExpiredError);
  });

  it('turns a step-up challenge (401 insufficient_user_authentication, RFC 9470) into StepUpRequiredError', async () => {
    const call = vi.fn().mockRejectedValue(new ApiError(401, 'insufficient_user_authentication'));

    await expect(withFreshIdToken(async () => 'password-only-id-token', call)).rejects.toBeInstanceOf(StepUpRequiredError);
  });

  it("leaves the vault routes' own 401s and every other failure as they are", async () => {
    const badSignature = new ApiError(401, 'vault_request_signature_invalid');
    const forbidden = new ApiError(403, 'forbidden');

    await expect(
      withFreshIdToken(
        async () => 't',
        () => Promise.reject(badSignature)
      )
    ).rejects.toBe(badSignature);
    await expect(
      withFreshIdToken(
        async () => 't',
        () => Promise.reject(forbidden)
      )
    ).rejects.toBe(forbidden);
  });
});
