/**
 * Login page — opened in a new tab by the iframe.
 * Immediately redirects to Keycloak for OIDC authentication.
 */
import { Loader } from '@gouvfr-lasuite/cunningham-react';
import { useEffect, useRef, useState } from 'react';

import { startLogin } from '@encryption/src/ui/auth/oidc-client';

export function LoginPage() {
  const started = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const searchParams = new URLSearchParams(window.location.search);
    const expectedSub = searchParams.get('expectedSub') ?? undefined;
    const forceLogin = searchParams.get('forceLogin') === '1';

    startLogin(expectedSub, forceLogin).catch((err) => {
      console.error('[encryption] Failed to start OIDC login:', err);
      setError(err instanceof Error ? err.message : String(err));
    });
  }, []);

  if (error) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '100vh',
          gap: '16px',
          padding: '24px',
        }}
      >
        <span style={{ fontSize: '48px' }}>⚠️</span>
        <p style={{ color: '#c00', fontWeight: 600, textAlign: 'center' }}>Authentication failed</p>
        <p style={{ color: '#666', fontSize: '14px', textAlign: 'center', maxWidth: '400px' }}>{error}</p>
        <p style={{ color: '#999', fontSize: '12px', textAlign: 'center', maxWidth: '400px' }}>
          This may happen if the encryption service cannot reach the identity provider. Check that the OIDC configuration is correct.
        </p>
        <button
          onClick={() => window.close()}
          style={{
            marginTop: '8px',
            padding: '8px 24px',
            background: '#0063CB',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          Close
        </button>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
      <Loader />
    </div>
  );
}
