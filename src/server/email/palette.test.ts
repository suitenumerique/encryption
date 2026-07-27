import { renderToMjml } from '@faire/mjml-react/utils/renderToMjml';
import mjml2html from 'mjml';

import { StandardLayout } from '@encryption/src/server/email/layout';
import { EmailPalette, applyEmailPaletteOverride, emailPalette } from '@encryption/src/server/email/palette';

async function renderLayoutHtml(): Promise<string> {
  const result = await mjml2html(renderToMjml(StandardLayout({ locale: 'en', title: 'Test', children: null })));

  return result.html;
}

describe('applyEmailPaletteOverride', () => {
  const defaults: EmailPalette = { ...emailPalette };

  afterEach(() => {
    Object.assign(emailPalette, defaults);
    jest.restoreAllMocks();
  });

  it('re-themes the rendered email, in both the inline colours and the generated CSS', async () => {
    // brandPrimary lands as an inline button colour and as the link colour in the
    // stylesheet, so a single override should surface in both parts of the HTML.
    applyEmailPaletteOverride({ brandPrimary: '#abcdef' });

    const html = await renderLayoutHtml();

    expect(html).toContain('#abcdef');
    // The default it replaced must be gone.
    expect(html).not.toContain(defaults.brandPrimary);
  });

  it('reads the override lazily, so a value set after module load still applies', async () => {
    // The styles were once frozen at module load; this guards that regression by
    // overriding a colour that only appears through the CSS getters (dark background).
    applyEmailPaletteOverride({ darkBody: '#123456' });

    const html = await renderLayoutHtml();

    expect(html).toContain('#123456');
  });

  it('ignores unknown keys and non-string values, keeping the defaults', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});

    applyEmailPaletteOverride({ notAColour: '#000000', brandPrimary: 42 as unknown as string });

    expect(emailPalette.brandPrimary).toBe(defaults.brandPrimary);
    expect(warn).toHaveBeenCalledTimes(2);
  });
});
