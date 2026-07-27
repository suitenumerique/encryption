import { startEmergencyJobs } from '@encryption/src/server/emergency-jobs';
import { env } from '@encryption/src/server/env';
import { createServer } from '@encryption/src/server/server';

async function main() {
  const app = await createServer();

  app.listen({ port: env.PORT, host: env.HOST }, (err, address) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }

    app.log.info(`Server listening at ${address}`);
    app.log.info(`Vault: ${env.VAULT_URL}`);
    app.log.info(`UI: ${env.UI_URL}`);

    // Notification cron (emergency access reminders/timeouts). Deliberately
    // outside createServer so test-built servers never start timers.
    const stopEmergencyJobs = startEmergencyJobs();

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
          await stopEmergencyJobs();
          await app.close();
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
