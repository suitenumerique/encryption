/**
 * Turns the tool's build into ONE self-contained HTML file: the script and the
 * stylesheet inlined, and a Content-Security-Policy that names them by hash and
 * allows nothing else. `default-src 'none'` leaves no `connect-src`, so the page
 * can make no request at all, even on a networked computer: the guarantee an
 * operator relies on when typing the maintenance phrase into it.
 *
 * Plain functions over strings, so they are tested without running a build; the
 * Vite plugin in vite.config.ts only feeds them the bundle.
 */
import { createHash } from 'node:crypto';

const sha256 = (text: string) => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;

export function contentSecurityPolicy(script: string, style: string): string {
  return [
    "default-src 'none'",
    // libsodium compiles its WebAssembly module from bytes embedded in the script.
    `script-src ${sha256(script)} 'wasm-unsafe-eval'`,
    `style-src ${sha256(style)}`,
    // The preview of a decrypted image, as a data: URL.
    'img-src data:',
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');
}

/**
 * Inline `script` and `style` into `html` in place of the tags Vite emitted for
 * them. A literal `</script` inside the script would end the element early, so it
 * is escaped in a way JavaScript reads identically (inside a string or regular
 * expression, `<\/` is `</`).
 */
export function inlineIntoHtml(html: string, script: string, style: string): string {
  const safeScript = script.replace(/<\/(script)/gi, '<\\/$1');

  // After a `<!--`, a `<script` puts the HTML parser in a state where the closing
  // tag no longer ends the element, and no rewrite of it is read identically by
  // JavaScript in every context (a u-flag regular expression, String.raw...). No
  // bundle has one today: refuse it, so a dependency adding one fails the build.
  if (script.includes('<!--')) throw new Error("The tool's script contains `<!--`, which can keep the HTML parser from closing it");
  const scriptTags = html.match(/<script\b[^>]*\bsrc="[^"]*"[^>]*><\/script>/g) ?? [];
  const styleTags = html.match(/<link\b[^>]*\brel="stylesheet"[^>]*>/g) ?? [];

  if (scriptTags.length !== 1 || styleTags.length > 1) {
    throw new Error(`Expected one script and at most one stylesheet in the tool's HTML, got ${scriptTags.length} and ${styleTags.length}`);
  }

  const csp = `<meta http-equiv="Content-Security-Policy" content="${contentSecurityPolicy(safeScript, style)}" />`;

  // Functions as replacements, so a `$&` or `$1` inside the bundle is never read as a pattern.
  let output = html.replace(scriptTags[0], () => `<script type="module">${safeScript}</script>`);

  output =
    styleTags.length === 1
      ? output.replace(styleTags[0], () => `<style>${style}</style>`)
      : output.replace('</head>', () => `<style>${style}</style></head>`);

  if (!/<meta charset="[^"]+"\s*\/?>/i.test(output)) throw new Error("The tool's HTML must declare its charset first");

  return output.replace(/<meta charset="[^"]+"\s*\/?>/i, (charset) => `${charset}\n    ${csp}`);
}
