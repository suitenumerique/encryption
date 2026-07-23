/**
 * The configured API client every interface call goes through.
 *
 * The endpoint functions themselves are generated from the routes' Zod schemas
 * (`npm run api:schema:sync`), so this module only carries what codegen cannot
 * know: how this app authenticates, and how it wants failures surfaced.
 */
import { translateApiError } from '@encryption/src/i18n';
import { createClient, createConfig } from '@encryption/src/ui/api/generated/client';
import type { ClientOptions } from '@encryption/src/ui/api/generated/types.gen';

/**
 * Server failures carry a stable `code` (never a message), which the frontend
 * translates. Kept as a thrown error rather than the client's `{ data, error }`
 * tuple because the crypto flows are imperative sequences whose call sites
 * branch on `err.code` inside a try/catch.
 */
export class ApiError extends Error {
  code: string;
  params?: Record<string, unknown>;
  status: number;

  constructor(status: number, code: string, params?: Record<string, unknown>, serverMessage?: string) {
    // Translated when the UI knows the code; otherwise falls back to the
    // server's English default rather than a generic "unknown error".
    super(translateApiError({ code, params, message: serverMessage }));
    this.name = 'ApiError';
    this.code = code;
    this.params = params;
    this.status = status;
  }
}

// In production the interface and the API share an origin; in dev the Vite
// proxy forwards /api to Fastify. Either way the paths are same-origin.
export const apiClient = createClient(createConfig<ClientOptions>({ baseUrl: '', throwOnError: true }));

// Turn every non-2xx into an ApiError before it reaches a call site. The body is
// the `{ code, params? }` shape declared by `errorResponses()` on the routes.
apiClient.interceptors.error.use((error, response) => {
  const body = (error ?? {}) as { code?: string; params?: Record<string, unknown>; message?: string };

  // `response` is absent only when the request never completed (network error);
  // 0 keeps the status numeric without pretending an HTTP status was returned.
  return new ApiError(response?.status ?? 0, body.code ?? 'unknown', body.params, body.message);
});

/**
 * Spread into every SDK call: `{ ...apiDefaults, headers: … }`.
 *
 * `throwOnError` has to be pinned HERE rather than only on the client, because
 * the generated functions declare it as a generic defaulting to false
 * (`<ThrowOnError extends boolean = false>`) and TypeScript resolves that per
 * call, not from the client's runtime config. Without it every result is typed
 * as the "may have failed" union, which is what forces `data!` and `response?.`
 * at call sites even though a failure would have thrown.
 */
export const apiDefaults = { client: apiClient, throwOnError: true } as const;

/** Bearer auth for the routes that take an OIDC token. */
export function authHeaders(token: string): { Authorization: string } {
  return { Authorization: `Bearer ${token}` };
}

/**
 * Covered vault routes additionally require a per-request identity signature,
 * produced by the vault (the interface holds the token, not the identity key).
 */
export function signedHeaders(token: string, xSignature: string): { Authorization: string; 'X-Signature': string } {
  return { Authorization: `Bearer ${token}`, 'X-Signature': xSignature };
}

/**
 * The path an approve call targets, exposed so the caller can obtain a matching
 * identity signature from the vault before invoking the endpoint.
 */
export function approveDevicePath(requestId: string): string {
  return `/api/vault/approvals/${encodeURIComponent(requestId)}/approve`;
}
