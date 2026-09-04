// TypeScript's `lib.dom.d.ts` (5.9) still ships no Trusted Types definitions.
// `@types/trusted-types` is present in the tree, but only as a transitive dependency
// of mermaid -> dompurify, and it is not picked up automatically, so relying on it
// would tie the build to a dev-only dependency of an internal-docs component. Only
// what this codebase actually uses is declared here.
//
// `lib.dom.d.ts` is generated from Web IDL filtered by browser-compat-data, and
// Trusted Types only became Baseline in February 2026, so it was excluded until now.
// TypeScript-DOM-lib-generator#2074 restores it; delete this file once it lands in a
// TypeScript release.
//
// `TrustedHTML` is NOT declared here: `@types/react` already declares it globally,
// and React types `dangerouslySetInnerHTML.__html` as `string | TrustedHTML`.

interface TrustedScriptURL {
  toString(): string;
}

interface TrustedTypePolicy {
  readonly name: string;
  createHTML(input: string): TrustedHTML;
  createScriptURL(input: string): TrustedScriptURL;
}

interface TrustedTypePolicyFactory {
  /**
   * Rejected by the browser when the CSP `trusted-types` directive does not list
   * `name`, and, absent `'allow-duplicates'`, when `name` was already created.
   */
  createPolicy(name: string, rules: { createHTML?(input: string): string; createScriptURL?(input: string): string }): TrustedTypePolicy;
}

interface Window {
  // Absent outside browsers that implement Trusted Types, in which case the CSP
  // directive is ignored too and a plain string stays acceptable.
  readonly trustedTypes?: TrustedTypePolicyFactory;
}
