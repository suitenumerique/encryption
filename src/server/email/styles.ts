import { emailPalette as c } from '@encryption/src/server/email/palette';

// MJML bakes colors into element attributes (no CSS variables), so dark mode is
// patched afterwards by targeting a class on each themeable element (body-wrapper,
// content-card, body-text, email-button). The patch runs in two forms: a
// `prefers-color-scheme` media query for real mail clients, and a rule scoped
// under Storybook's manual dark-mode class (which does not flip that media query).
//
// The light backgrounds live on the elements themselves (inline mj-attributes), so
// they render in the Storybook preview too (which injects the email HTML into a
// <div>, where a bare `body {}` rule would target the page, not the email). The
// dark overrides below use `!important` to beat those inline values.

// The palette can be overridden at startup (EMAIL_PALETTE_PATH), so the CSS is
// built lazily on each render rather than frozen into a module-load const, which
// would capture the default colours before any override is applied.
function baseStyles(): string {
  return `
hr {
  color: ${c.dividerLight};
}

a {
  color: ${c.brandPrimary};
  text-underline-offset: 3px;
}

h1,
h2 {
  line-height: 1.2em;
}

.logo-dark {
  display: none;
}
`;
}

// The p selector on buttons is needed because on Storybook a button without a link renders a paragraph instead of an anchor
function darkStyles(scope: string): string {
  const prefix = scope ? `${scope} ` : '';

  return `
${prefix}a {
  color: ${c.brandPrimaryDark} !important;
}

/* The CTA button is an <a> too, so the rule above would repaint its label the
   body-link blue (fails contrast on the brand background). Re-assert the button's
   own on-brand text; its background stays brand-550 in both themes. The p covers
   Storybook, where a button with no link renders as a paragraph. */
${prefix}.email-button a,
${prefix}.email-button p {
  color: ${c.onBrand} !important;
}

${prefix}h1,
${prefix}h2 {
  color: ${c.headingDark} !important;
}

${prefix}.body-text,
${prefix}.body-text div {
  color: ${c.bodyTextDark} !important;
}

${prefix}.content-card,
${prefix}.content-card > table {
  background: ${c.darkCard} !important;
}

${prefix}hr {
  color: ${c.headingDark} !important;
}

${prefix}.divider > p {
  border-color: ${c.dividerDark} !important;
}

${prefix}.logo-light {
  display: none !important;
}

${prefix}.logo-dark {
  display: block !important;
}
`;
}

export function getEmailStyles(): string {
  return `
:root {
  color-scheme: light dark;
  supported-color-schemes: light dark;
}

${baseStyles()}

@media (prefers-color-scheme: dark) {
  body,
  .body-wrapper {
    background: ${c.darkBody} !important;
  }

  ${darkStyles('')}
}
`;
}

export function getStorybookStyles(): string {
  return `
${baseStyles()}

body.sb-show-main.dark,
body.sb-show-main.dark .body-wrapper {
  background: ${c.darkBody} !important;
}

${darkStyles('body.sb-show-main.dark')}
`;
}
