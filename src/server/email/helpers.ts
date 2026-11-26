import { compile } from 'html-to-text';

export const convertHtmlEmailToText = compile({
  wordwrap: 130,
  selectors: [
    { selector: 'head', format: 'skip' },
    { selector: '.logo-section', format: 'skip' },
    { selector: '.social-network-section', format: 'skip' },
  ],
});
