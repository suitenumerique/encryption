import { interfaceContextSchema } from '@encryption/src/shared/schemas/interface-context';

describe('interfaceContextSchema', () => {
  it('should accept a context with only suiteUserId', () => {
    const result = interfaceContextSchema.parse({ suiteUserId: 'me' });

    expect(result.suiteUserId).toBe('me');
    expect(result.verifyRecipients).toBeUndefined();
    expect(result.recipientProfile).toBeUndefined();
  });

  it('should accept a verifyRecipients block with labeled recipients', () => {
    const result = interfaceContextSchema.parse({
      suiteUserId: 'me',
      verifyRecipients: { recipients: { u1: { email: 'u1@example.test' }, u2: { email: 'u2@example.test', name: 'Bob' } } },
    });

    expect(result.verifyRecipients?.recipients.u2).toEqual({ email: 'u2@example.test', name: 'Bob' });
  });

  it('should accept a recipientProfile block', () => {
    const result = interfaceContextSchema.parse({
      suiteUserId: 'me',
      recipientProfile: { userId: 'u1', label: { email: 'u1@example.test', name: 'Alice' } },
    });

    expect(result.recipientProfile?.userId).toBe('u1');
    expect(result.recipientProfile?.label.email).toBe('u1@example.test');
  });

  it('should reject a recipient label with no email', () => {
    expect(() =>
      interfaceContextSchema.parse({
        suiteUserId: 'me',
        verifyRecipients: { recipients: { u1: { name: 'Alice' } } },
      })
    ).toThrow();
  });

  it('should reject a recipientProfile with no userId', () => {
    expect(() =>
      interfaceContextSchema.parse({
        suiteUserId: 'me',
        recipientProfile: { label: { email: 'u1@example.test' } },
      })
    ).toThrow();
  });
});
