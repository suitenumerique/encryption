import { startEmergencyJobs } from '@encryption/src/server/emergency-jobs';
import { env } from '@encryption/src/server/env';
import { captureServerError, flushMonitoring, initMonitoring, isMonitoringEnabled } from '@encryption/src/server/monitoring';
import { getBuildVersion } from '@encryption/src/server/routes/versions';
import { createServer } from '@encryption/src/server/server';
import { startVaultPurgeJobs } from '@encryption/src/server/vault-purge-jobs';

async function main() {
  // Optional: with no SENTRY_DSN this is a no-op and nothing is ever sent.
  initMonitoring({
    dsn: env.SENTRY_DSN,
    environment: env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? 'production',
    release: env.SENTRY_RELEASE || env.SOURCE_COMMIT || getBuildVersion(),
  });

  const app = await createServer();

  if (isMonitoringEnabled()) {
    app.log.info('Error reporting enabled');
  }

  // A throw outside a request never reaches the Fastify error handler, and these
  // are the ones worth waking someone for. Logged and reported, then left to Node's
  // default behaviour: the process must still die on an uncaught exception rather
  // than continue in an unknown state.
  process.on('unhandledRejection', (reason) => {
    app.log.error(reason);
    captureServerError(reason, { tags: { code: 'unhandledRejection' } });
  });

  process.on('uncaughtException', (error) => {
    app.log.error(error);
    captureServerError(error, { tags: { code: 'uncaughtException' } });

    void flushMonitoring().finally(() => process.exit(1));
  });

  app.listen({ port: env.PORT, host: env.HOST }, (err, address) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }

    app.log.info(`Server listening at ${address}`);
    app.log.info(`Vault: ${env.VAULT_URL}`);
    app.log.info(`UI: ${env.UI_URL}`);

    // A wildcard lets every matching subdomain embed the vault and drive it for the
    // signed-in user, decryption included: any compromised page under it becomes a
    // compromised product. Allowed, but worth saying where it matters.
    if (process.env.NODE_ENV !== 'development' && env.ALLOWED_FRAME_ANCESTORS.includes('*')) {
      app.log.warn(
        'ALLOWED_FRAME_ANCESTORS contains a wildcard: every matching subdomain can embed the vault and ask it to decrypt for the signed-in user. Prefer an explicit list of product origins.'
      );
    }

    // Scheduled jobs (emergency access reminders/timeouts, dormant vault
    // retention). Deliberately outside createServer so test-built servers never
    // start timers.
    const stopEmergencyJobs = startEmergencyJobs();
    const stopVaultPurgeJobs = startVaultPurgeJobs();

    // Graceful shutdown for a real deployment: an orchestrator sends SIGTERM, then
    // SIGKILLs after a grace period, and Fastify does not drain on its own. In dev
    // there is no orchestrator, and long-lived dev connections (Vite HMR, the demo
    // SSE) would keep app.close() pending — so leave Ctrl+C to Node's instant
    // default there instead of hanging until tsx force-kills.
    if (process.env.NODE_ENV !== 'development') {
      let shuttingDown = false;
      const shutdown = async (signal: string) => {
        if (shuttingDown) return;
        shuttingDown = true;
        app.log.info(`${signal} received, shutting down`);

        // Never hang: if draining stalls on a long-lived connection, exit anyway.
        const forced = setTimeout(() => process.exit(0), 10_000);
        forced.unref();

        try {
          await Promise.all([stopEmergencyJobs(), stopVaultPurgeJobs()]);
          await app.close();
          await flushMonitoring();
        } catch (closeErr) {
          app.log.error(closeErr);
        }

        process.exit(0);
      };

      process.on('SIGTERM', () => void shutdown('SIGTERM'));
      process.on('SIGINT', () => void shutdown('SIGINT'));
    }
  });
}

main();
