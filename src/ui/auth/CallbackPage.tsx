/**
 * OIDC callback page: where the identity provider sends the sign-in tab back.
 * It checks the state and deposits the authorization code on the server, where
 * the interface iframe that started the sign-in collects it (see login.ts). It
 * never sees an ID token, and needs no link to the iframe, which a provider
 * page may have cut on the way.
 */
import { Button, Loader, VariantType } from '@gouvfr-lasuite/ui-components';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { UnknownCallbackError, depositCallback } from '@encryption/src/ui/auth/login';
import { Notice } from '@encryption/src/ui/components/layout/Screen';

export function CallbackPage() {
  const { t } = useTranslation('common');
  const [error, setError] = useState<string | null>(null);
  const [deposited, setDeposited] = useState(false);
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;

    depositCallback()
      .then(() => {
        setDeposited(true);
        // Allowed for a tab a script opened; the message below stays otherwise.
        window.close();
      })
      .catch((err: unknown) => {
        // A provider's own `error_description` stays as it wrote it, in its language.
        if (err instanceof UnknownCallbackError) setError(t('auth.unknown_callback'));
        else setError(err instanceof Error ? err.message : String(err));
      });
  }, [t]);

  if (error || deposited) {
    return (
      <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Notice type={error ? VariantType.ERROR : VariantType.SUCCESS}>{error ? t('auth.failed', { error }) : t('auth.success')}</Notice>
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
          <Button onClick={() => window.close()}>{t('settings.close')}</Button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', gap: '1rem' }}>
      <Loader />
    </div>
  );
}
