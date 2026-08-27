/**
 * Optional error reporting to a Sentry-compatible collector.
 *
 * Entirely optional: with no `SENTRY_DSN` the module is inert, sends nothing, and
 * the project runs exactly as before. Nothing here is required for the service to
 * work, and no deployment is obliged to run a collector.
 *
 * WHY THIS IS NOT THE SENTRY SDK
 *
 * This is an end-to-end encryption service, so the failure mode of a monitoring
 * tool is not "noisy issues", it is "a private key or a passphrase left the
 * machine". The SDK's value comes from capturing context automatically: request
 * bodies, headers, breadcrumbs, local variables, spans. That is exactly the
 * behaviour we must not have, and configuring it off is a weaker guarantee than
 * never having it: CVE-2025-65944 (November 2025) is precisely that story, where
 * `Authorization` and `Cookie` headers reached Sentry through trace span
 * attributes, and Sentry's own server-side scrubbing missed them too because it
 * reused the SDK's matching logic.
 *
 * So the payload here is built field by field from an allowlist. There is no
 * automatic instrumentation to surprise us, no request object in scope, and the
 * whole surface is one file that a reviewer can read in a few minutes. It speaks
 * Sentry's public envelope API, so it works against Sentry, a self-hosted Sentry,
 * or GlitchTip, with no dependency added to the tree.
 *
 * WHAT IS ALLOWED OUT
 *
 * - the error type, its message and its stack, each passed through `redact()`
 * - a fixed set of tag names (route, method, status, host, report type, error code)
 * - the environment and release identifiers
 *
 * Everything else is absent by construction: no request body, no headers, no
 * cookies, no user identity, no breadcrumbs, no local variables.
 */
import { randomUUID } from 'node:crypto';

import { symbolicateBrowserFrames } from '@encryption/src/server/symbolicate';

export interface MonitoringConfig {
  dsn: string;
  environment: string;
  release?: string;
}

export interface SentryEndpoint {
  url: string;
  publicKey: string;
}

/** The only tag names that may leave. Anything else is dropped, not redacted. */
const ALLOWED_TAGS = ['route', 'method', 'status', 'host', 'reportType', 'code'] as const;

export type AllowedTag = (typeof ALLOWED_TAGS)[number];

/** Beyond this, a message is truncated rather than sent whole. */
const MAX_TEXT_LENGTH = 500;

/** Deepest frames kept. A stack longer than this is noise for grouping anyway. */
const MAX_FRAMES = 30;

/** Sent per rolling window, after which events are dropped rather than queued. */
const MAX_EVENTS_PER_WINDOW = 30;
const WINDOW_MS = 60_000;

/**
 * A Sentry DSN is `https://<publicKey>@<host>/<path>/<projectId>`. Returns the
 * envelope endpoint and the key, or null for anything unparseable, so a typo
 * disables reporting instead of crashing the server at boot.
 */
export function parseDsn(dsn: string): SentryEndpoint | null {
  let parsed: URL;

  try {
    parsed = new URL(dsn);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  if (!parsed.username) return null;

  const segments = parsed.pathname.split('/').filter(Boolean);
  const projectId = segments.pop();

  if (!projectId) return null;

  const prefix = segments.length > 0 ? `/${segments.join('/')}` : '';

  return {
    url: `${parsed.protocol}//${parsed.host}${prefix}/api/${projectId}/envelope/`,
    publicKey: parsed.username,
  };
}

const EMAIL_PATTERN = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
// A run of 32+ base64url/hex characters with no separator: a key, a wrapped blob,
// a JWT segment, a mnemonic-derived value. Real prose never looks like this, and
// file paths break on `/` and `.` so stack traces survive intact.
const OPAQUE_TOKEN_PATTERN = /[A-Za-z0-9_-]{32,}/g;

/**
 * Last line of defence before any text leaves the process. Applied to every string
 * sent, including the ones we believe are safe: the point is that a message we did
 * not anticipate cannot carry key material out.
 */
export function redact(value: string, maxLength: number = MAX_TEXT_LENGTH): string {
  const scrubbed = value.replace(EMAIL_PATTERN, '[email]').replace(OPAQUE_TOKEN_PATTERN, '[redacted]');

  return scrubbed.length > maxLength ? `${scrubbed.slice(0, maxLength)}…` : scrubbed;
}

export interface SentryFrame {
  filename?: string;
  function?: string;
  lineno?: number;
  colno?: number;
  in_app: boolean;
}

const FRAME_PATTERN = /^\s*at\s+(?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?$/;

/**
 * Parses `error.stack` into Sentry frames, oldest first, which is the order the
 * event format expects. Frame text is redacted like everything else: a stack can
 * embed an argument through a function name in some engines.
 */
export function parseStack(stack: string | undefined): SentryFrame[] {
  if (!stack) return [];

  const frames: SentryFrame[] = [];

  for (const line of stack.split('\n')) {
    const match = FRAME_PATTERN.exec(line);

    if (!match) continue;

    const [, fn, filename, lineno, colno] = match;

    frames.push({
      function: fn ? redact(fn, 120) : undefined,
      filename: redact(filename, 200),
      lineno: Number(lineno),
      colno: Number(colno),
      // Anything not inside node_modules is ours, which is what Sentry groups on.
      in_app: !filename.includes('node_modules'),
    });
  }

  return frames.slice(0, MAX_FRAMES).reverse();
}

/**
 * A frame's file is a path or a URL, and it is what Sentry matches against uploaded
 * artifacts, so the general redactor must not touch it: one scrubbed character and
 * symbolication silently stops working. A query string is dropped instead, since
 * that is the only part of a URL that carries anything.
 */
export function redactPath(value: string): string {
  const withoutQuery = value.split(/[?#]/)[0];

  return withoutQuery.length > 300 ? withoutQuery.slice(0, 300) : withoutQuery;
}

// Firefox and Safari format frames as `name@url:line:column`, with no `at`.
const BROWSER_FRAME_PATTERN = /^\s*(?:at\s+)?(?:(.*?)[@(])?((?:https?|file|blob):[^\s)]+?|[^\s(@)]+):(\d+):(\d+)\)?\s*$/;

/**
 * Parses a stack produced by a BROWSER, which is not the V8 format `parseStack`
 * handles. Frames keep the full asset URL, because that is what an uploaded source
 * map is matched against.
 */
export function parseBrowserStack(stack: string | undefined): SentryFrame[] {
  if (!stack) return [];

  const frames: SentryFrame[] = [];

  for (const line of stack.split('\n')) {
    const match = BROWSER_FRAME_PATTERN.exec(line);

    if (!match) continue;

    const [, fn, filename, lineno, colno] = match;

    frames.push({
      function: fn ? redact(fn.trim(), 120) : undefined,
      filename: redactPath(filename),
      lineno: Number(lineno),
      colno: Number(colno),
      // Our own bundles, as opposed to an extension's content script.
      in_app: !filename.startsWith('chrome-extension:') && !filename.startsWith('moz-extension:'),
    });
  }

  return frames.slice(0, MAX_FRAMES).reverse();
}

export type EventLevel = 'error' | 'warning' | 'info';

export interface CaptureContext {
  level?: EventLevel;
  tags?: Partial<Record<AllowedTag, string | number | undefined>>;
}

export interface SentryEvent {
  event_id: string;
  timestamp: number;
  platform: 'node' | 'javascript';
  level: EventLevel;
  logger: string;
  environment: string;
  release?: string;
  tags: Record<string, string>;
  message?: { formatted: string };
  exception?: { values: { type: string; value: string; stacktrace?: { frames: SentryFrame[] } }[] };
}

function buildTags(tags: CaptureContext['tags']): Record<string, string> {
  const built: Record<string, string> = {};

  for (const key of ALLOWED_TAGS) {
    const value = tags?.[key];

    if (value === undefined || value === null) continue;

    built[key] = redact(String(value), 120);
  }

  return built;
}

/**
 * Builds the exact JSON that will be sent. Exported so a test can assert on the
 * payload itself rather than on the configuration meant to constrain it.
 */
export interface CaptureSubject {
  error?: unknown;
  message?: string;
  /** A failure that happened in a browser: already parsed, no Error to unwrap. */
  browserError?: { name: string; message: string; frames: SentryFrame[] };
}

export function buildEvent(
  config: Pick<MonitoringConfig, 'environment' | 'release'>,
  subject: CaptureSubject,
  context: CaptureContext = {},
  eventId: string = randomUUID().replace(/-/g, '')
): SentryEvent {
  const event: SentryEvent = {
    event_id: eventId,
    timestamp: Date.now() / 1000,
    platform: 'node',
    level: context.level ?? 'error',
    logger: 'encryption',
    environment: config.environment,
    ...(config.release ? { release: config.release } : {}),
    tags: buildTags(context.tags),
  };

  if (subject.message !== undefined) {
    event.message = { formatted: redact(subject.message) };
  }

  if (subject.browserError !== undefined) {
    const { name, message, frames } = subject.browserError;

    event.platform = 'javascript';
    event.exception = {
      values: [
        {
          type: redact(name, 120),
          value: redact(message),
          ...(frames.length > 0 ? { stacktrace: { frames } } : {}),
        },
      ],
    };

    return event;
  }

  if (subject.error !== undefined) {
    const error = subject.error;
    const isError = error instanceof Error;

    event.exception = {
      values: [
        {
          type: isError ? redact(error.name, 120) : 'UnknownError',
          value: redact(isError ? error.message : String(error)),
          ...(isError && error.stack ? { stacktrace: { frames: parseStack(error.stack) } } : {}),
        },
      ],
    };
  }

  return event;
}

export function buildEnvelope(event: SentryEvent, sentAt: string): string {
  const header = JSON.stringify({ event_id: event.event_id, sent_at: sentAt });
  const itemHeader = JSON.stringify({ type: 'event' });

  return `${header}\n${itemHeader}\n${JSON.stringify(event)}\n`;
}

interface MonitoringState {
  config: MonitoringConfig;
  endpoint: SentryEndpoint;
  windowStartedAt: number;
  sentInWindow: number;
  pausedUntil: number;
  inFlight: Set<Promise<void>>;
}

let state: MonitoringState | null = null;

/**
 * Enables reporting. Returns false when there is no DSN or the DSN is unusable,
 * which is the normal case for a local run and for any deployment that does not
 * want a collector.
 */
export function initMonitoring(config: Partial<MonitoringConfig> | undefined): boolean {
  state = null;

  if (!config?.dsn) return false;

  const endpoint = parseDsn(config.dsn);

  if (!endpoint) return false;

  state = {
    config: { dsn: config.dsn, environment: config.environment ?? 'unknown', release: config.release },
    endpoint,
    windowStartedAt: Date.now(),
    sentInWindow: 0,
    pausedUntil: 0,
    inFlight: new Set(),
  };

  return true;
}

export function isMonitoringEnabled(): boolean {
  return state !== null;
}

/** Test seam: forget any configuration, so a suite cannot leak into the next. */
export function resetMonitoring(): void {
  state = null;
}

function allowedToSend(now: number): boolean {
  if (state === null) return false;
  if (now < state.pausedUntil) return false;

  if (now - state.windowStartedAt > WINDOW_MS) {
    state.windowStartedAt = now;
    state.sentInWindow = 0;
  }

  if (state.sentInWindow >= MAX_EVENTS_PER_WINDOW) return false;

  state.sentInWindow += 1;

  return true;
}

async function deliver(current: MonitoringState, event: SentryEvent): Promise<void> {
  try {
    const response = await fetch(current.endpoint.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-sentry-envelope',
        'X-Sentry-Auth': `Sentry sentry_version=7, sentry_client=encryption/1.0, sentry_key=${current.endpoint.publicKey}`,
      },
      body: buildEnvelope(event, new Date().toISOString()),
      signal: AbortSignal.timeout(5000),
    });

    if (response.status === 429) {
      // Back off for what the collector asks, defaulting to a minute, so a burst
      // of errors cannot turn into a burst of outbound requests.
      const retryAfter = Number(response.headers.get('retry-after'));

      current.pausedUntil = Date.now() + (Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 60_000);
    }
  } catch {
    // Monitoring must never affect the request that triggered it, and a collector
    // being down is not this service's problem.
  }
}

/**
 * Fire and forget. The caller is on a request path, so nothing here is awaited and
 * nothing here can throw; `flushMonitoring()` exists for shutdown.
 */
function capture(subject: CaptureSubject, context: CaptureContext): void {
  const current = state;

  if (current === null || !allowedToSend(Date.now())) return;

  const pending = deliver(current, buildEvent(current.config, subject, context));

  current.inFlight.add(pending);
  void pending.finally(() => current.inFlight.delete(pending));
}

export function captureServerError(error: unknown, context: CaptureContext = {}): void {
  capture({ error }, { level: 'error', ...context });
}

export function captureServerMessage(message: string, context: CaptureContext = {}): void {
  capture({ message }, { level: 'warning', ...context });
}

/**
 * A failure reported by the interface. The stack arrives as text from a browser, so
 * it is parsed into frames here (a collector resolves `stacktrace.frames`, never text
 * inside a message), and then resolved against the source maps sitting next to the
 * bundles in this image, so what leaves is `src/ui/....tsx:73` rather than a column
 * of a minified chunk. Nothing is uploaded anywhere for that to work.
 */
export function captureBrowserError(report: { name?: string; message?: string; stack?: string }, context: CaptureContext = {}): void {
  capture(
    {
      browserError: {
        name: report.name ?? 'Error',
        message: report.message ?? '',
        frames: symbolicateBrowserFrames(parseBrowserStack(report.stack)),
      },
    },
    { level: 'error', ...context }
  );
}

/** Lets a graceful shutdown give in-flight reports a chance to land. */
export async function flushMonitoring(): Promise<void> {
  if (state === null) return;

  await Promise.allSettled([...state.inFlight]);
}
