import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { CSS_MODULES, cssModuleClassKeys, cssModuleDeclaration, declarationPath } from '@encryption/src/build/css-module-types';

describe('css module types', () => {
  it('turns BEM selectors into the keys Vite exports and ignores global ones', () => {
    const css = `
      .screen__title--error { color: red; }
      .actions > :global(.c__button) { width: 100%; }
      .chip :global(.material-icons) { font-size: 16px; }
      /* .commented { } */
      .card, .card--warning:hover { border: 0; }
    `;

    expect(cssModuleClassKeys(css)).toEqual(['actions', 'card', 'cardWarning', 'chip', 'screenTitleError']);
  });

  for (const cssPath of CSS_MODULES) {
    it(`${declarationPath(cssPath)} is up to date (run \`npm run css:types\`)`, () => {
      expect(readFileSync(declarationPath(cssPath), 'utf8')).toBe(cssModuleDeclaration(readFileSync(cssPath, 'utf8')));
    });
  }
});
