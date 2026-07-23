import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const FILES = ['faq.mdx', 'faq_fr.mdx'] as const;

function headings(file: string): string[] {
  const source = readFileSync(resolve(__dirname, file), 'utf8');

  // Heading LEVELS only, not their text: the wording is translated, the
  // structure must not be.
  return source
    .split('\n')
    .filter((line) => /^#{1,6}\s/.test(line))
    .map((line) => line.match(/^#+/)![0]);
}

function alerts(file: string): string[] {
  const source = readFileSync(resolve(__dirname, file), 'utf8');

  return [...source.matchAll(/<Alert severity="(\w+)"/g)].map((match) => match[1]);
}

/**
 * The FAQ is translated by FILE rather than by i18n key, so each locale stays
 * readable markdown on GitHub. The cost is that the two can drift silently: a
 * section added to one language and not the other is invisible until a reader
 * in that language notices it is missing. These assertions are the tripwire.
 *
 * Translation rules (they live here rather than at the top of the .mdx files,
 * because prettier rewrites MDX comments into markdown italics):
 * keep the same sections, same order, same headings; translate the prose only,
 * never product names, algorithm names or technical values (XChaCha20-Poly1305,
 * X25519, 2FA...). `faq.mdx` is English, `faq_fr.mdx` is French, and only the
 * FAQ is translated: `../technical/integration.mdx` and `architecture.md` are
 * English-only, for integrators and auditors respectively.
 */
describe('user FAQ translations', () => {
  it('has the same heading structure in every locale', () => {
    const [reference, ...others] = FILES.map((file) => headings(file));

    for (const other of others) {
      expect(other).toEqual(reference);
    }
  });

  it('carries the same alerts, in the same order and severity', () => {
    const [reference, ...others] = FILES.map((file) => alerts(file));

    for (const other of others) {
      expect(other).toEqual(reference);
    }
  });

  it('keeps the locales genuinely translated rather than copy-pasted', () => {
    const [en, fr] = FILES.map((file) => readFileSync(resolve(__dirname, file), 'utf8'));

    expect(fr).not.toEqual(en);
  });
});
