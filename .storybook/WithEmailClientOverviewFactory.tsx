import { Decorator } from '@storybook/react';
import { CSSProperties, ReactElement } from 'react';

import { useEmailHtml } from '@encryption/.storybook/StorybookRenderer';
import { convertHtmlEmailToText } from '@encryption/src/server/email/helpers';

// Inline styles instead of a stylesheet so the overview stays self-contained (no CSS
// modules pipeline needed). Colours are Cunningham contextual tokens, so the overview
// chrome (subject bar, badges, plaintext) transitions with the Storybook theme like
// every other story, rather than being pinned to one mode.
const styles = {
  panel: {
    background: 'var(--c--contextuals--background--surface--primary, #ffffff)',
    color: 'var(--c--contextuals--content--semantic--neutral--primary, #1b1c1d)',
  },
  header: {
    background: 'var(--c--contextuals--background--surface--secondary, #f2f2f2)',
    color: 'var(--c--contextuals--content--semantic--neutral--primary, #1b1c1d)',
    padding: '16px',
    fontFamily: "'Helvetica Neue', Helvetica, arial, sans-serif",
  },
  subject: {
    margin: 0,
    fontFamily: 'monospace',
    fontSize: '14px',
  },
  container: {
    display: 'flex',
    flexDirection: 'row',
    padding: '20px',
  },
  badge: {
    display: 'inline-block',
    marginBottom: '12px',
    fontSize: '12px',
    textTransform: 'uppercase',
    backgroundColor: 'var(--c--contextuals--content--semantic--neutral--secondary, #444444)',
    padding: '3px 6px',
    letterSpacing: '0.05em',
    fontWeight: 500,
    borderRadius: '3px',
    color: 'var(--c--contextuals--background--surface--primary, #ffffff)',
    fontFamily: "'Helvetica Neue', Helvetica, arial, sans-serif",
  },
  html: {
    flex: '0.6 0 0',
    borderRight: '1px solid var(--c--contextuals--border--surface--primary, #dddddd)',
    marginRight: '20px',
    paddingRight: '20px',
  },
  plaintext: {
    flex: '0.4 0 0',
  },
  plaintextContent: {
    paddingTop: '24px',
    fontFamily: 'monospace',
    whiteSpace: 'pre-wrap',
  },
} satisfies Record<string, CSSProperties>;

/**
 * Shows the HTML rendering side by side with the plaintext alternative, under
 * the exact subject line. Both are derived from the SAME real email HTML
 * (mjml -> html -> html-to-text), so the plaintext matches what a mail client
 * receives rather than being computed off the raw MJML tags. The subject follows
 * the locale toolbar, like the email body.
 */
function EmailClientOverview({ story, subject }: { story: ReactElement; subject: string }) {
  const html = useEmailHtml(story);

  if (html === null) return null;

  return (
    <article style={styles.panel}>
      <header style={styles.header}>
        <p style={styles.subject}>Subject: {subject}</p>
      </header>
      <main style={styles.container}>
        <section style={styles.html}>
          <span style={styles.badge}>HTML</span>
          <div dangerouslySetInnerHTML={{ __html: html }} />
        </section>
        <section style={styles.plaintext}>
          <span style={styles.badge}>Plaintext</span>
          <div style={styles.plaintextContent}>{convertHtmlEmailToText(html)}</div>
        </section>
      </main>
    </article>
  );
}

export function WithEmailClientOverviewFactory(subjectFor: (locale: string) => string): Decorator {
  const decorator: Decorator = function EmailClientOverviewDecorator(Story, context) {
    const locale = (context.globals.locale as string) ?? 'en';

    return <EmailClientOverview story={<Story />} subject={subjectFor(locale)} />;
  };

  return decorator;
}
