import { prisma } from '@encryption/src/prisma/client';
import { captureServerError } from '@encryption/src/server/monitoring';

export interface ScheduledJob {
  /** Names the Postgres advisory lock, so two jobs never block each other. */
  lockKey: string;
  intervalMs: number;
  /** How long one run may hold the lock: well under the interval, well over a realistic batch. */
  lockTimeoutMs: number;
  run: (nowMs: number) => Promise<void>;
  label: string;
}

/**
 * Multi-instance safety: each run takes a Postgres transaction-scoped advisory
 * lock, so concurrent servers never run the same job twice; the loser skips the
 * run entirely and the next tick catches up.
 *
 * The run's own reads and writes deliberately go through the global client, not
 * `tx`: each row is processed (and stamped) independently, so a run that dies
 * halfway must KEEP what it already did rather than roll it back and re-send
 * those emails on the next tick. The transaction exists only to hold the lock.
 *
 * Which is why the timeout has to be raised: Prisma's default interactive
 * transaction timeout is 5s, and a run that sends a handful of emails over SMTP
 * blows through it. The transaction would abort and RELEASE THE LOCK while the
 * run is still going, which is exactly the concurrent double-send the lock is
 * there to prevent.
 */
async function runWithAdvisoryLock(job: ScheduledJob): Promise<void> {
  await prisma.$transaction(
    async (tx) => {
      // hashtext gives a stable int4 from the key; the xact-scoped lock releases
      // itself with the transaction, so a crashed run can never wedge the lock.
      const [{ locked }] = await tx.$queryRaw<[{ locked: boolean }]>`SELECT pg_try_advisory_xact_lock(hashtext(${job.lockKey})) AS locked`;
      if (!locked) return;

      await job.run(Date.now());
    },
    { timeout: job.lockTimeoutMs, maxWait: 2_000 }
  );
}

/**
 * Called once from main.ts after listen; never from createServer (tests build
 * servers without timers). Returns a stop function for graceful shutdown: it
 * cancels the schedule and awaits any in-flight run so the process does not exit
 * mid-transaction (though the advisory lock is xact-scoped, so an abrupt kill
 * would roll back safely anyway).
 */
export function startScheduledJob(job: ScheduledJob): () => Promise<void> {
  let inFlight: Promise<void> = Promise.resolve();
  const tick = () => {
    inFlight = runWithAdvisoryLock(job).catch((err) => {
      console.error(`${job.label} run failed`, err);
      captureServerError(err, { tags: { code: job.lockKey } });
    });

    return inFlight;
  };

  void tick();
  const interval = setInterval(tick, job.intervalMs);
  interval.unref();

  return async () => {
    clearInterval(interval);
    await inFlight;
  };
}
