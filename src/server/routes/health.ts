import type { FastifyInstance } from 'fastify';

import { prisma } from '@encryption/src/prisma/client';
import { env } from '@encryption/src/server/env';

/**
 * Three levels, one per Kubernetes probe, because each failure calls for a different
 * reaction:
 *
 * - `/health`: the process answers. Liveness. Depending on anything else here would turn
 *   an outage of that thing into a restart loop of every pod, which repairs nothing.
 * - `/health/ready`: the server serves what it exists to serve. It asks ITSELF, through
 *   the same hooks and routing as a real request, for the interface page, a vault file and
 *   an API route that reads no database. "The process answers" says nothing about those:
 *   a registration mistake once made every page a 404 while `/health` stayed green.
 * - `/health/startup`: the above, plus a query on a real table. Only while a pod boots, so
 *   a pod whose database settings are wrong (refused connection, missing migration) never
 *   becomes ready and a rollout keeps the working pods. Not part of readiness on purpose:
 *   the vault decrypts locally, and must stay reachable while the database is down.
 *
 * The bodies say which check fails and nothing more: these endpoints are public.
 */

// light-my-request puts this on the injected socket. Not an IP address, so no real
// connection can carry it, which lets the access log skip the self-requests safely.
export const SELF_CHECK_REMOTE_ADDRESS = 'self-check';

const CACHE_MS = 5_000;
const DATABASE_TIMEOUT_MS = 3_000;

type CheckStatus = 'ok' | 'failing' | 'skipped';
type Checks = Record<string, CheckStatus>;

interface Report {
  status: 'ok' | 'failing';
  checks: Checks;
}

const isDev = process.env.NODE_ENV === 'development';

async function serves(app: FastifyInstance, host: string, url: string, contentType: string): Promise<CheckStatus> {
  try {
    const response = await app.inject({ method: 'GET', url, headers: { host }, remoteAddress: SELF_CHECK_REMOTE_ADDRESS });

    return response.statusCode === 200 && String(response.headers['content-type']).includes(contentType) ? 'ok' : 'failing';
  } catch {
    return 'failing';
  }
}

async function databaseAnswers(app: FastifyInstance): Promise<CheckStatus> {
  let timer: NodeJS.Timeout | undefined;

  try {
    await Promise.race([
      // A real table, not `SELECT 1`: a database that accepts the connection but was never
      // migrated is as unusable as one that refuses it.
      prisma.user.findFirst({ select: { id: true } }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('database check timed out')), DATABASE_TIMEOUT_MS);
      }),
    ]);

    return 'ok';
  } catch (error) {
    app.log.warn({ err: error }, 'health: the database check failed');

    return 'failing';
  } finally {
    clearTimeout(timer);
  }
}

async function servingChecks(app: FastifyInstance): Promise<Checks> {
  // In development Vite serves the two hosts, from source, and there is nothing built to check.
  const skipped: CheckStatus = 'skipped';
  const [interfacePage, vaultFile, api] = await Promise.all([
    isDev ? skipped : serves(app, env.UI_HOST, '/', 'text/html'),
    isDev ? skipped : serves(app, env.VAULT_HOST, '/vault.js', 'javascript'),
    serves(app, env.UI_HOST, '/api/version', 'application/json'),
  ]);

  return { interface: interfacePage, vault: vaultFile, api };
}

function report(checks: Checks): Report {
  return { status: Object.values(checks).includes('failing') ? 'failing' : 'ok', checks };
}

// Probes come every few seconds, from every node, and the endpoints are public: one
// evaluation per window, whoever asks.
function cached(evaluate: () => Promise<Report>): () => Promise<Report> {
  let last: { at: number; value: Promise<Report> } | undefined;

  return () => {
    if (!last || Date.now() - last.at > CACHE_MS) {
      last = { at: Date.now(), value: evaluate() };
    }

    return last.value;
  };
}

export async function healthRoute(app: FastifyInstance): Promise<void> {
  // `hide` keeps infrastructure endpoints out of the generated OpenAPI document.
  const hidden = { schema: { hide: true } };

  const ready = cached(async () => report(await servingChecks(app)));
  const startup = cached(async () => {
    const [serving, database] = await Promise.all([servingChecks(app), databaseAnswers(app)]);

    return report({ ...serving, database });
  });

  app.get('/health', hidden, async () => ({ status: 'ok' }));

  app.get('/health/ready', hidden, async (_, reply) => {
    const result = await ready();

    return reply.code(result.status === 'ok' ? 200 : 503).send(result);
  });

  app.get('/health/startup', hidden, async (_, reply) => {
    const result = await startup();

    return reply.code(result.status === 'ok' ? 200 : 503).send(result);
  });
}
