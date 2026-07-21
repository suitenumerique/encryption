/**
 * Stable error codes that travel across the vault iframe ↔ client
 * postMessage boundary. Consumers (drive / docs / meet) match on these
 * instead of regexing error messages — message text is for logs / humans
 * and may change, the codes are part of the SDK contract.
 *
 * Why a string-keyed const (not a TS enum): keeps the runtime values
 * tree-shakeable, and the strings double as wire identifiers when
 * marshalled over postMessage.
 */
export const VaultErrorCode = {
  /** No key pair stored locally on this device — user must onboard. */
  MISSING_KEYS: 'MISSING_KEYS',
  /**
   * AEAD verification failed. Either the ciphertext is for a different
   * recipient (their wrapped symmetric key was encrypted against another
   * pubkey) or the underlying KEM secret didn't match. Bubbles up from
   * libsodium's "wrong secret key for the given ciphertext".
   */
  WRONG_SECRET_KEY: 'WRONG_SECRET_KEY',
  /** Backup payload is corrupted, truncated, or from an unsupported version. */
  INVALID_BACKUP: 'INVALID_BACKUP',
  /** BIP-39-style mnemonic input that doesn't checksum. */
  INVALID_MNEMONIC: 'INVALID_MNEMONIC',
  /** Caller hit a vault method without first calling `init()`. */
  NOT_INITIALIZED: 'NOT_INITIALIZED',
  /** `setAuthContext({ suiteUserId })` was never called. */
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  /**
   * The declared sub could not be resolved to an internal encryption user id:
   * no local alias, and no directory row (either the user never onboarded, or
   * the registry was unreachable with nothing cached). Thrown by every vault
   * operation EXCEPT `has-keys`, which responds `{ hasKeys: false }` instead
   * of throwing: for that probe, "unresolvable" and "never onboarded" are the
   * same answer, and products use it to decide whether to offer onboarding.
   */
  UNRESOLVED_USER: 'UNRESOLVED_USER',
  /** Privileged operation attempted from a non-encryption-origin caller. */
  PRIVILEGED_ORIGIN_REQUIRED: 'PRIVILEGED_ORIGIN_REQUIRED',
  /** A vault request didn't get an answer within the configured timeout. */
  TIMEOUT: 'TIMEOUT',
  /** Vault module loaded outside an iframe (origin-isolation invariant). */
  IFRAME_REQUIRED: 'IFRAME_REQUIRED',
  /** Ciphertext / encrypted-key payload too short to be valid (truncated). */
  CIPHERTEXT_TOO_SHORT: 'CIPHERTEXT_TOO_SHORT',
  /** Blob's leading version byte doesn't match a format this build can decode. */
  UNSUPPORTED_CRYPTO_VERSION: 'UNSUPPORTED_CRYPTO_VERSION',
  /** A signature public key didn't have the expected Ed25519 length. */
  INVALID_SIGNATURE_KEY: 'INVALID_SIGNATURE_KEY',
  /**
   * A registry entry's binding signature did not verify against its claimed
   * identity (signature) key — the directory record is forged, tampered, or
   * incoherent. Consumers MUST refuse to trust / share with such an entry.
   */
  INVALID_KEY_BINDING: 'INVALID_KEY_BINDING',
  /**
   * A pulled vault failed its integrity check: the identity-signed manifest did
   * not verify, an item's ciphertext hash or coverage did not match, or the
   * revision rolled back. Distinct from a wrong recovery phrase (which fails the
   * unlock, not the integrity check) — it means the SERVER served tampered or
   * incoherent vault data, so the user must be warned, not told to re-type.
   */
  VAULT_INTEGRITY_FAILED: 'VAULT_INTEGRITY_FAILED',
  /**
   * A wrap was attempted for a recipient whose identity is not TOFU-'trusted'
   * with a matching fingerprint (refused, never verified, or a fingerprint
   * mismatch that may be a MITM-substituted key). The vault refuses to wrap the
   * symmetric key until the recipient's identity is verified. The offending
   * userIds are in the error message.
   */
  UNTRUSTED_RECIPIENT: 'UNTRUSTED_RECIPIENT',
  /**
   * A write-through change (e.g. a TOFU decision) could not be pushed to the
   * server, so it was NOT kept locally either — the caller should surface a
   * "couldn't save, retry" and the local state is unchanged. Distinct from a
   * network throw (which also aborts before persisting).
   */
  SYNC_FAILED: 'SYNC_FAILED',
  /**
   * Catch-all for situations the SDK couldn't classify into a more
   * specific code — present so consumers always have something to switch
   * on rather than falling back to message regex.
   */
  UNKNOWN: 'UNKNOWN',
} as const;

export type VaultErrorCode = (typeof VaultErrorCode)[keyof typeof VaultErrorCode];

/**
 * Error subclass tagged with a stable {@link VaultErrorCode}. Throw this
 * (instead of `new Error(...)`) anywhere inside the SDK so the boundary
 * marshaller can pass the code along to consumers.
 *
 * Note: `VaultError` instances DO NOT survive `structuredClone` — the
 * postMessage layer marshals `{ message, code }` explicitly and
 * reconstructs the class on the receiving side.
 */
export class VaultError extends Error {
  public readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
  }
}

export const isVaultError = (err: unknown): err is VaultError => {
  return err instanceof Error && (err as { code?: unknown }).code !== undefined && typeof (err as { code?: unknown }).code === 'string';
};

/**
 * Last-line-of-defence classifier. Used by the vault message handler when
 * an unexpected (non-VaultError) Error escapes — typically a libsodium
 * throw that we haven't wrapped. Returns UNKNOWN if no pattern matches,
 * which is still a stable code consumers can switch on.
 */
export const classifyVaultError = (err: unknown): VaultErrorCode => {
  if (err instanceof VaultError) return err.code;
  const msg = err instanceof Error ? err.message : typeof err === 'string' ? err : '';
  if (/wrong secret key/i.test(msg)) return VaultErrorCode.WRONG_SECRET_KEY;
  if (/no key pair/i.test(msg)) return VaultErrorCode.MISSING_KEYS;
  if (/invalid backup/i.test(msg)) return VaultErrorCode.INVALID_BACKUP;
  if (/invalid mnemonic|checksum mismatch/i.test(msg)) return VaultErrorCode.INVALID_MNEMONIC;
  if (/too short to be valid/i.test(msg)) return VaultErrorCode.CIPHERTEXT_TOO_SHORT;
  if (/unsupported crypto version/i.test(msg)) return VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION;
  if (/signature public key/i.test(msg)) return VaultErrorCode.INVALID_SIGNATURE_KEY;
  return VaultErrorCode.UNKNOWN;
};
