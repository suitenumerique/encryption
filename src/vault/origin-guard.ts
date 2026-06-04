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
    throw new Error('Vault must be loaded in an iframe');
  }
}

/**
 * Check if a message origin is in the allowed list.
 * Supports exact matches and wildcard subdomains (e.g., "https://*.example.com").
 */
export function isOriginAllowed(origin: string): boolean {
  return allowedOrigins.some((allowed) => {
    if (!allowed.includes('*')) {
      return origin === allowed;
    }

    // Parse both as URLs to compare protocol + domain parts
    try {
      const originUrl = new URL(origin);
      const allowedParts = allowed.match(/^(https?):\/\/(.+)$/);

      if (!allowedParts) return false;

      const [, allowedProtocol, allowedHost] = allowedParts;

      if (originUrl.protocol !== `${allowedProtocol}:`) return false;

      // Convert wildcard pattern to match: *.example.com matches sub.example.com
      // but NOT sub.sub.example.com (single level only)
      const hostPattern = allowedHost.replace(/\*/g, '[^.]+');

      return new RegExp(`^${hostPattern}$`).test(originUrl.host);
    } catch {
      return false;
    }
  });
}

/**
 * Check if a message origin is the encryption interface domain.
 * Only this origin can perform privileged operations (generate, export, import, destroy keys).
 */
export function isInterfaceOrigin(origin: string): boolean {
  return interfaceOrigin !== null && origin === interfaceOrigin;
}
