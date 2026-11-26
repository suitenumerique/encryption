/**
 * The server hands the browser its runtime configuration (OIDC endpoints, the vault
 * URL, the allowed origins) in a `<script type="application/json">` data block rather
 * than an inline script.
 *
 * A data block is not executable, so `script-src 'self'` needs neither a hash nor a
 * nonce for it, and everything that DOES execute remains the SRI-pinned bundle. That
 * is the property an inline script cannot keep: its content depends on deployment
 * environment variables, so no build-time hash or signature can ever cover it.
 */
import type { ZodType } from 'zod';

export const RUNTIME_CONFIG_ELEMENT_ID = 'encryption-runtime-config';

/**
 * Escaping `<` is the entire rule, and one character is enough precisely BECAUSE this
 * is a data block and not inline JavaScript: `>` cannot close a tag on its own, `&`
 * starts no entity inside a raw-text element, and U+2028/U+2029 are line terminators
 * in JS source but ordinary characters to `JSON.parse`. Escaping every `<` therefore
 * makes `</script` and `<!--` unrepresentable, which are the only two sequences that
 * can end the block. `JSON.parse` restores them.
 */
export function buildRuntimeConfigBlock(config: object): string {
  const json = JSON.stringify(config).replaceAll('<', '\\u003c');

  // A post-condition rather than trust in the line above: an edit that weakens the
  // escaping fails loudly at startup instead of silently allowing markup injection.
  if (json.includes('<')) {
    throw new Error('runtime config still carries a raw "<" after escaping');
  }

  return `<script type="application/json" id="${RUNTIME_CONFIG_ELEMENT_ID}">${json}</script>`;
}

/**
 * Read at module load by the `runtime-config` module of each side, so the module graph
 * orders it before anything that consumes it.
 *
 * Absent means Storybook or a unit test, which render without a server: an empty
 * object, and every consumer already falls back per field. PRESENT means the server
 * served it, so it is validated in full and a missing or mistyped field throws. Every
 * field maps to an env var the server validates at boot, so an incomplete block is
 * evidence of a corrupted document rather than of a deployment left unconfigured.
 */
export function readRuntimeConfigBlock<T extends object>(schema: ZodType<T>): Readonly<Partial<T>> {
  const element = typeof document === 'undefined' ? null : document.getElementById(RUNTIME_CONFIG_ELEMENT_ID);

  if (!element?.textContent) {
    return Object.freeze({});
  }

  return Object.freeze(schema.parse(JSON.parse(element.textContent)));
}
