// Renders a translated string that carries inline markup (e.g. <strong>). Values
// interpolated into it are escaped upstream by `tHtml`, so only the translation's
// own static markup is treated as HTML.
export function EmailHtml({ html }: { html: string }) {
  return <span dangerouslySetInnerHTML={{ __html: html }} />;
}
