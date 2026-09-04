import { UI_TRUSTED_TYPES_POLICY } from '@encryption/src/shared/constants';

// `require-trusted-types-for 'script'` makes the browser refuse a plain string at
// every DOM injection sink, so the few places that legitimately hand over markup have
// to mint it here. Created once, at module load, before any component renders: the
// CSP names this policy alone and refuses a second `createPolicy` under it, so
// injected code can neither replace it nor register one of its own.
//
// Undefined in browsers without Trusted Types, where the CSP directive is ignored
// too and a plain string remains acceptable.
const policy = window.trustedTypes?.createPolicy(UI_TRUSTED_TYPES_POLICY, {
  createHTML: (markup) => markup,
});

// Anything that would run script rather than describe content. The inputs here are
// built by us at build time from our own documentation, so this is a tripwire on
// trusted input rather than a sanitizer: it catches an escaping bug in the
// highlighter or the diagram renderer, not a hostile author. Treat it as the reason
// to look, never as the reason to trust.
const EXECUTABLE_MARKUP = /<\s*script|\son[a-z]+\s*=|javascript:|<\s*iframe|srcdoc\s*=/i;

/**
 * The ONE conversion point for pre-rendered markup in the interface. Every caller is
 * a place that produces HTML from our own sources; a new caller means a new thing to
 * review, which is the whole point of routing them through here.
 */
export function toTrustedMarkup(markup: string): string {
  if (EXECUTABLE_MARKUP.test(markup)) {
    throw new Error('refusing to inject markup that carries script');
  }

  // `TrustedHTML` where the browser supports it, a plain string otherwise. Callers
  // pass it to `dangerouslySetInnerHTML`, whose React type is `string | TrustedHTML`.
  return (policy ? policy.createHTML(markup) : markup) as string;
}
