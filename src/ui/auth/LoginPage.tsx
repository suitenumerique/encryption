/**
 * Sign-in page, opened in a new tab by the interface iframe. Asks the iframe for
 * the sign-in's parameters, then goes to the identity provider through the
 * server. Refuses to start when nothing on the interface's origin opened it.
 */
import { Button, Loader, VariantType } from '@gouvfr-lasuite/ui-components';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { receiveLoginParameters, startLogin } from '@encryption/src/ui/auth/login';
import { Notice } from '@encryption/src/ui/components/layout/Screen';

export function LoginPage() {
  const { t } = useTranslation('common');
  const started = useRef(false);
  const [noOpener, setNoOpener] = useState(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    void receiveLoginParameters().then((parameters) => {
      if (parameters) startLogin(parameters);
      else setNoOpener(true);
    });
  }, []);

  if (noOpener) {
    return (
      <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Notice type={VariantType.ERROR}>{t('auth.no_opener')}</Notice>
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
          <Button onClick={() => window.close()}>{t('settings.close')}</Button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
      <Loader />
    </div>
  );
}
