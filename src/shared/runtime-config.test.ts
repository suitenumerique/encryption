/**
 * @jest-environment jsdom
 */
import { z } from 'zod';

import { RUNTIME_CONFIG_ELEMENT_ID, buildRuntimeConfigBlock, readRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';

const schema = z.object({ vaultUrl: z.string().url(), docsEnabled: z.boolean() });

function serve(block: string | null): void {
  document.head.innerHTML = block ?? '';
}

describe('buildRuntimeConfigBlock', () => {
  it('escapes every "<" so a value cannot close the element', () => {
    const block = buildRuntimeConfigBlock({ note: '</script><script>alert(1)</script>', nested: { a: '<!--' } });

    expect(block).not.toContain('</script><script>');
    expect(block).toContain('\\u003c');
    // Exactly one closing tag: the block's own.
    expect(block.match(/<\/script>/g)).toHaveLength(1);
  });

  it('round-trips the escaped characters through JSON.parse', () => {
    const value = '</script>&<!-- ';
    const json = buildRuntimeConfigBlock({ value })
      .replace(/^<script[^>]*>/, '')
      .replace(/<\/script>$/, '');

    expect(JSON.parse(json)).toEqual({ value });
  });
});

describe('readRuntimeConfigBlock', () => {
  it('returns nothing when the document carries no block, as in Storybook and unit tests', () => {
    serve(null);

    expect(readRuntimeConfigBlock(schema)).toEqual({});
  });

  it('validates a served block in full', () => {
    serve(buildRuntimeConfigBlock({ vaultUrl: 'https://data.encryption.test', docsEnabled: true }));

    expect(readRuntimeConfigBlock(schema)).toEqual({ vaultUrl: 'https://data.encryption.test', docsEnabled: true });
  });

  it.each([
    ['a missing field', { vaultUrl: 'https://data.encryption.test' }],
    ['a mistyped field', { vaultUrl: 'https://data.encryption.test', docsEnabled: 'yes' }],
    ['a malformed url', { vaultUrl: 'not-a-url', docsEnabled: true }],
  ])('throws on %s, which means a corrupted document rather than an unconfigured one', (_label, config) => {
    serve(buildRuntimeConfigBlock(config));

    expect(() => readRuntimeConfigBlock(schema)).toThrow();
  });

  it('throws rather than guessing when the block is not valid JSON', () => {
    serve(`<script type="application/json" id="${RUNTIME_CONFIG_ELEMENT_ID}">{ nope</script>`);

    expect(() => readRuntimeConfigBlock(schema)).toThrow();
  });
});
