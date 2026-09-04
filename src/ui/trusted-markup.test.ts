/**
 * @jest-environment jsdom
 */
import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

describe('toTrustedMarkup', () => {
  it('passes through the markup a highlighter produces', () => {
    expect(toTrustedMarkup('<span class="hljs-keyword">const</span> x')).toBe('<span class="hljs-keyword">const</span> x');
  });

  // A tripwire on trusted input, not a sanitizer: these inputs come from our own
  // documentation, so a hit means the highlighter or the diagram renderer broke.
  it.each([
    ['a script tag', '<script>alert(1)</script>'],
    ['an event handler', '<img src=x onerror="alert(1)">'],
    ['a javascript: url', '<a href="javascript:alert(1)">x</a>'],
    ['a nested frame', '<iframe src="//evil.example"></iframe>'],
  ])('refuses markup carrying %s', (_label, markup) => {
    expect(() => toTrustedMarkup(markup)).toThrow('refusing to inject markup that carries script');
  });
});
