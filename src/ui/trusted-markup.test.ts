/**
 * @vitest-environment jsdom
 */
import { describe, expect, it } from 'vitest';

import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

describe('toTrustedMarkup', () => {
  it('passes through the markup a highlighter produces', () => {
    expect(toTrustedMarkup('<span class="hljs-keyword">const</span> x')).toBe('<span class="hljs-keyword">const</span> x');
  });

  // These are TEXT, not attributes. An event-handler pattern that is not anchored
  // inside a tag matches them, and a documented snippet naming a variable `online`
  // would then take the whole documentation page down.
  it.each([
    ['a variable whose name starts with "on"', '<span class="hljs-keyword">let</span> online = true'],
    ['a highlighted assignment', '<span class="hljs-keyword">const</span> once = <span class="hljs-number">5</span>'],
  ])('does not trip on %s', (_label, markup) => {
    expect(toTrustedMarkup(markup)).toBe(markup);
  });

  // A tripwire on trusted input, not a sanitizer: these inputs come from our own
  // documentation, so a hit means the highlighter or the diagram renderer broke.
  it.each([
    ['a script tag', '<script>alert(1)</script>'],
    ['an event handler', '<img src=x onerror="alert(1)">'],
    ['a javascript: url', '<a href="javascript:alert(1)">x</a>'],
    ['a nested frame', '<iframe src="//evil.example"></iframe>'],
    ['a srcdoc attribute', '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>'],
  ])('refuses markup carrying %s', (_label, markup) => {
    expect(() => toTrustedMarkup(markup)).toThrow('refusing to inject markup that carries script');
  });
});
