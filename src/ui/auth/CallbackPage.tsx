/**
 * OIDC callback page — handles the redirect from Keycloak.
 * Opened in a new tab (same tab as LoginPage after Keycloak redirect).
 *
 * 1. Exchanges the authorization code for tokens
 * 2. Posts the tokens to `window.opener`, which is the interface iframe
 * 3. Closes the tab
 */
import { Alert, Button, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { WrongUserError, handleCallback, notifyAuthComplete, startLogin } from '@encryption/src/ui/auth/oidc-client';

export function CallbackPage() {
  const { t } = useTranslation('common');
  const [error, setError] = useState<string | null>(null);
  const [wrongUserExpectedSub, setWrongUserExpectedSub] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [unacknowledged, setUnacknowledged] = useState(false);
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;

    (async () => {
      try {
        const tokenSet = await handleCallback();

        setSuccess(true);

        // Closing only on an acknowledgement, never on a timer. See notifyAuthComplete:
        // a tab that closes on success alone tells whoever opened it that the signed-in
        // user matched the `expectedSub` they put in the URL, and it also hides the case
        // where the token reached nobody.
        if (await notifyAuthComplete(tokenSet)) {
          window.close();
        } else {
          setUnacknowledged(true);
        }
      } catch (err) {
        if (err instanceof WrongUserError) {
          setError('wrong_user');
          setWrongUserExpectedSub(err.expectedSub);
        } else {
          setError((err as Error).message);
        }
      }
    })();
  }, []);

  if (error === 'wrong_user') {
    return (
      <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={VariantType.WARNING}>{t('auth.wrong_user')}</Alert>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginTop: '1.5rem' }}>
          <Button onClick={() => void startLogin(wrongUserExpectedSub ?? undefined, true)}>{t('auth.sign_in_another_account')}</Button>
          <Button color="neutral" onClick={() => window.close()}>
            {t('settings.close')}
          </Button>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={VariantType.ERROR}>{t('auth.failed', { error })}</Alert>
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
          <Button onClick={() => window.close()}>{t('settings.close')}</Button>
        </div>
      </div>
    );
  }

  if (success) {
    return (
      <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={unacknowledged ? VariantType.WARNING : VariantType.SUCCESS}>
          {t(unacknowledged ? 'auth.not_acknowledged' : 'auth.success')}
        </Alert>
        {unacknowledged && (
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
            <Button onClick={() => window.close()}>{t('settings.close')}</Button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', gap: '1rem' }}>
      <Loader />
    </div>
  );
}
