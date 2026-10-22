// Shared by the vault (which answers `has-keys`), the interface and the client SDK.

/** This browser held the user's vault and forgot it after VAULT_DEVICE_INACTIVITY_DAYS without use. */
export interface DeEnrollment {
  deEnrolledAt: number;
  inactivityDays: number;
}

export interface HasKeysResult {
  hasKeys: boolean;
  /** Set while this browser holds no vault because it forgot it for inactivity, until it is enrolled again. */
  deEnrolled?: DeEnrollment;
}
