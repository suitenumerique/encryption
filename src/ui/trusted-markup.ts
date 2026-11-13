import { UI_TRUSTED_TYPES_POLICY } from '@encryption/src/shared/constants';

const policy = window.trustedTypes?.createPolicy(UI_TRUSTED_TYPES_POLICY, {
  createHTML: (markup) => markup,
});

// Anything that would run script rather than describe content. The inputs here are
// produced from our own documentation by the highlighter and the diagram renderer, so
// this is a tripwire on trusted input rather than a sanitizer: it catches an escaping
// bug in one of those two, not a hostile author. Treat a hit as the reason to look,
// never as the reason to trust what got through.
//
// Every attribute pattern is anchored inside a tag (`<[a-z][^>]*`, which cannot cross
// a `>`), because these inputs carry arbitrary TEXT as well as markup: a documented
// snippet reading `let online = true` ends up as ` online = ` in the highlighter's
// output and an unanchored `\son[a-z]+\s*=` would throw on it, taking the whole
// documentation page down over a variable name.
const EXECUTABLE_MARKUP = /<\s*(?:script|iframe)\b|<[a-z][^>]*(?:\son[a-z]+\s*=|\ssrcdoc\s*=|javascript:)/i;

// Only point to access the policy
export function toTrustedMarkup(markup: string): string | TrustedHTML {
  if (EXECUTABLE_MARKUP.test(markup)) {
    throw new Error('refusing to inject markup that carries script');
  }

  return policy ? policy.createHTML(markup) : markup;
}
