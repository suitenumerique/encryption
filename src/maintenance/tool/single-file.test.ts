import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { contentSecurityPolicy, inlineIntoHtml } from '@encryption/src/maintenance/tool/single-file';

const VITE_HTML = `<!doctype html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>tool</title>
    <script type="module" crossorigin src="./assets/index-abc.js"></script>
    <link rel="stylesheet" crossorigin href="./assets/index-def.css">
  </head>
  <body><div id="root"></div></body>
</html>`;

const hash = (text: string) => `'sha256-${createHash('sha256').update(text).digest('base64')}'`;

describe('inlineIntoHtml', () => {
  it('inlines both files and allows exactly them, and nothing that could reach a network', () => {
    const html = inlineIntoHtml(VITE_HTML, 'console.log(1)', 'body{margin:0}');

    expect(html).not.toMatch(/src=|href=/);
    expect(html).toContain('<script type="module">console.log(1)</script>');
    expect(html).toContain('<style>body{margin:0}</style>');
    expect(html).toContain(`content="${contentSecurityPolicy('console.log(1)', 'body{margin:0}')}"`);
    expect(contentSecurityPolicy('a', 'b')).toBe(
      `default-src 'none'; script-src ${hash('a')} 'wasm-unsafe-eval'; style-src ${hash('b')}; img-src data:; base-uri 'none'; form-action 'none'`
    );
    // The policy comes right after the charset, before anything it governs.
    expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<script'));
  });

  it('keeps a script containing "</script" inside one element, hashed as written', () => {
    const script = 'const tag = "</script>"; const re = /<\\/SCRIPT/;';
    const html = inlineIntoHtml(VITE_HTML, script, '');
    const written = 'const tag = "<\\/script>"; const re = /<\\/SCRIPT/;';

    expect(html.match(/<\/script>/g)).toHaveLength(1);
    expect(html).toContain(`<script type="module">${written}</script>`);
    expect(html).toContain(hash(written));
  });

  it('refuses a script containing "<!--", which no escaping keeps from swallowing the closing tag', () => {
    expect(() => inlineIntoHtml(VITE_HTML, 'const html = "<!--<script>";', '')).toThrow(/<!--/);
  });

  it('reads a bundle that contains replacement patterns literally', () => {
    expect(inlineIntoHtml(VITE_HTML, 'x.replace(/a/, "$&$1")', '')).toContain('x.replace(/a/, "$&$1")');
  });

  it('refuses a page with another shape than the one it knows how to fold', () => {
    expect(() => inlineIntoHtml(VITE_HTML.replace(/<script[^>]*><\/script>/, ''), 'x', '')).toThrow(/one script/);
    expect(() => inlineIntoHtml(VITE_HTML.replace('<meta charset="UTF-8" />', ''), 'x', '')).toThrow(/charset/);
  });
});
