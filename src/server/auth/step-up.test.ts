import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { hasSecondFactor, isFreshAuthentication, requireStepUp, satisfiesStepUp } from '@encryption/src/server/auth/step-up';
import { env } from '@encryption/src/server/env';

vi.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_STEP_UP_ENABLED: true,
    OIDC_STEP_UP_ACR_VALUES: ['eidas1-mfa', 'eidas2'],
    OIDC_STEP_UP_AMR_VALUES: ['mfa', 'totp'],
    OIDC_STEP_UP_MAX_AGE_SECONDS: 300,
  },
}));

const nowSeconds = () => Math.floor(Date.now() / 1000);

describe('hasSecondFactor', () => {
  it('accepts a second-factor acr, or a second-factor method among the amr', () => {
    expect(hasSecondFactor({ acr: 'eidas1-mfa' })).toBe(true);
    expect(hasSecondFactor({ acr: 'eidas1', amr: ['pwd', 'totp'] })).toBe(true);
    expect(hasSecondFactor({ amr: 'mfa' })).toBe(true);
  });

  it('refuses a password-only login, or one that says nothing', () => {
    expect(hasSecondFactor({ acr: 'eidas1', amr: ['pwd'] })).toBe(false);
    expect(hasSecondFactor({})).toBe(false);
  });

  it('has no policy to meet when no value is configured', () => {
    const { OIDC_STEP_UP_ACR_VALUES, OIDC_STEP_UP_AMR_VALUES } = env;

    try {
      Object.assign(env, { OIDC_STEP_UP_ACR_VALUES: [], OIDC_STEP_UP_AMR_VALUES: [] });
      expect(hasSecondFactor({})).toBe(true);
    } finally {
      Object.assign(env, { OIDC_STEP_UP_ACR_VALUES, OIDC_STEP_UP_AMR_VALUES });
    }
  });
});

describe('isFreshAuthentication', () => {
  it('accepts an authentication younger than the max age, tolerating a little clock skew', () => {
    expect(isFreshAuthentication({ auth_time: nowSeconds() - 60 })).toBe(true);
    expect(isFreshAuthentication({ auth_time: nowSeconds() + 10 })).toBe(true);
  });

  it('refuses an older one, and a token without auth_time', () => {
    expect(isFreshAuthentication({ auth_time: nowSeconds() - 301 })).toBe(false);
    expect(isFreshAuthentication({})).toBe(false);
  });
});

describe('satisfiesStepUp', () => {
  it('needs both: a second factor that is fresh', () => {
    expect(satisfiesStepUp({ acr: 'eidas2', auth_time: nowSeconds() })).toBe(true);
    expect(satisfiesStepUp({ acr: 'eidas2', auth_time: nowSeconds() - 3600 })).toBe(false);
    expect(satisfiesStepUp({ acr: 'eidas1', auth_time: nowSeconds() })).toBe(false);
  });

  it('lets everything through while the step-up is off', () => {
    try {
      Object.assign(env, { OIDC_STEP_UP_ENABLED: false });
      expect(satisfiesStepUp({})).toBe(true);
    } finally {
      Object.assign(env, { OIDC_STEP_UP_ENABLED: true });
    }
  });
});

describe('requireStepUp', () => {
  function buildApp(claims: Record<string, unknown> | undefined) {
    const app = Fastify();

    app.post('/sensitive', async (request, reply) => {
      request.idTokenClaims = claims as never;
      if (!requireStepUp(request, reply)) return reply;

      return { done: true };
    });

    return app;
  }

  it('lets a fresh second-factor ID token through', async () => {
    const response = await buildApp({ sub: 'u', exp: 0, acr: 'eidas1-mfa', auth_time: nowSeconds() }).inject({ method: 'POST', url: '/sensitive' });

    expect(response.json()).toEqual({ done: true });
  });

  it('answers the RFC 9470 challenge otherwise', async () => {
    const response = await buildApp({ sub: 'u', exp: 0, acr: 'eidas1', auth_time: nowSeconds() }).inject({ method: 'POST', url: '/sensitive' });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(
      'Bearer error="insufficient_user_authentication", error_description="A fresh authentication with a second factor is required", acr_values="eidas1-mfa eidas2", max_age="300"'
    );
    expect(response.json()).toEqual({ code: 'insufficient_user_authentication', params: { max_age: 300 } });
  });
});
