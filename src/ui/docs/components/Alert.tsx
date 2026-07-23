import type { ReactNode } from 'react';

interface AlertProps {
  severity: 'info' | 'warning' | 'error' | 'success';
  title?: string;
  children: ReactNode;
}

// Token family verified against Cunningham and against how docs/ and drive/ use
// it: severity is a SEGMENT (`--semantic--info--secondary`), not
// `--semantic--contextual--info`, which this repo had invented and which
// therefore always fell back to a hardcoded pastel in both themes. The real
// tokens flip with the theme (info-700 background / info-100 text in dark), so
// background and text can both come from the palette.
const severityVars: Record<AlertProps['severity'], { border: string; background: string; color: string }> = {
  info: {
    border: 'var(--c--globals--colors--info-500, #0063cb)',
    background: 'var(--c--contextuals--background--semantic--info--secondary)',
    color: 'var(--c--contextuals--content--semantic--info--secondary)',
  },
  warning: {
    border: 'var(--c--globals--colors--warning-500, #b34000)',
    background: 'var(--c--contextuals--background--semantic--warning--secondary)',
    color: 'var(--c--contextuals--content--semantic--warning--secondary)',
  },
  error: {
    border: 'var(--c--globals--colors--error-500, #ce0500)',
    background: 'var(--c--contextuals--background--semantic--error--secondary)',
    color: 'var(--c--contextuals--content--semantic--error--secondary)',
  },
  success: {
    border: 'var(--c--globals--colors--success-500, #18753c)',
    background: 'var(--c--contextuals--background--semantic--success--secondary)',
    color: 'var(--c--contextuals--content--semantic--success--secondary)',
  },
};

export function Alert({ severity, title, children }: AlertProps) {
  const vars = severityVars[severity];

  return (
    <div
      role="alert"
      style={{
        borderLeft: `4px solid ${vars.border}`,
        background: vars.background,
        color: vars.color,
        padding:
          'var(--c--globals--spacings--4, 16px) var(--c--globals--spacings--4, 16px) var(--c--globals--spacings--4, 16px) var(--c--globals--spacings--5, 20px)',
        margin: 'var(--c--globals--spacings--4, 16px) 0',
        borderRadius: '0 4px 4px 0',
        fontSize: 'var(--c--globals--font--sizes--s, 14px)',
        lineHeight: 1.6,
      }}
    >
      {title && (
        <p
          style={{
            margin: '0 0 var(--c--globals--spacings--2, 8px)',
            fontWeight: 'var(--c--globals--font--weights--bold, 700)' as unknown as number,
            fontSize: 'var(--c--globals--font--sizes--m, 15px)',
          }}
        >
          {title}
        </p>
      )}
      <div>{children}</div>
    </div>
  );
}
