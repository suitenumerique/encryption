import { isOriginInAllowlist } from '@encryption/src/shared/origin-allowlist';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

let allowedOrigins: string[] = [];
let interfaceOrigin: string | null = null;

/**
 * Initialize the origin guard with the list of allowed parent origins
 * and the encryption interface origin for privileged operations.
 */
export function initOriginGuard(origins: string[], interfaceEncryptionOrigin: string | null): void {
  allowedOrigins = origins;
  interfaceOrigin = interfaceEncryptionOrigin;
}

/**
 * Validate that the vault is loaded in an iframe (not directly).
 */
export function validateIframeContext(): void {
  if (window.self === window.top) {
    throw new VaultError(VaultErrorCode.IFRAME_REQUIRED, 'Vault must be loaded in an iframe');
  }
}

/**
 * Check if a message origin is in the allowed list, with the CSP `frame-ancestors`
 * matching rules the server applies to the same list.
 */
export function isOriginAllowed(origin: string): boolean {
  return isOriginInAllowlist(origin, allowedOrigins);
}

/**
 * Check if a message origin is the encryption interface domain.
 * Only this origin can perform privileged operations (generate, export, import, destroy keys).
 */
export function isInterfaceOrigin(origin: string): boolean {
  return interfaceOrigin !== null && origin === interfaceOrigin;
}
