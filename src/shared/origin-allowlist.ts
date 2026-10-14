/**
 * Whether an origin belongs to an `ALLOWED_FRAME_ANCESTORS`-style list.
 *
 * The same list becomes the CSP `frame-ancestors`, so entries follow its
 * host-source rules: an exact origin, or `scheme://*.base` for any subdomain of
 * `base`, at any depth (the CSP cannot express "one level only", and a page
 * allowed to embed the vault must also be allowed to talk to it and load its
 * SDK). A wildcard is only valid as the leftmost label.
 */
export function isOriginInAllowlist(origin: string, allowlist: readonly string[]): boolean {
  return allowlist.some((allowed) => {
    if (!allowed.includes('*')) {
      return origin === allowed;
    }

    try {
      const originUrl = new URL(origin);
      const allowedParts = allowed.match(/^(https?):\/\/\*\.([^*]+)$/);

      if (!allowedParts) return false;

      const [, allowedProtocol, base] = allowedParts;

      if (originUrl.protocol !== `${allowedProtocol}:`) return false;

      // The host must END with ".base" and have at least one label before it, so
      // neither the base itself nor "evilbase" or "base.evil" matches. The port is
      // part of `host`, so a base without a port only matches the default port.
      return originUrl.host.endsWith(`.${base.toLowerCase()}`);
    } catch {
      return false;
    }
  });
}

/**
 * Whether a configured entry is one the matcher above and the CSP agree on: an
 * http(s) origin written exactly as the browser serializes it (lowercase, no path,
 * no trailing slash), or the same with `*.` as its leftmost label. A lone `*`, a
 * bare host or a wildcard elsewhere would match nothing here but could widen the
 * CSP `frame-ancestors` built from the same list, so they are refused up front.
 */
export function isValidOriginEntry(entry: string): boolean {
  const wildcard = entry.match(/^(https?):\/\/\*\.(.+)$/);
  const origin = wildcard ? `${wildcard[1]}://${wildcard[2]}` : entry;

  if (origin.includes('*')) return false;

  try {
    const url = new URL(origin);

    return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin === origin;
  } catch {
    return false;
  }
}

export function parseOriginAllowlist(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
}
