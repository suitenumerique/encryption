import type { Plugin } from 'vite';

/**
 * Development only. While the dev server restarts, Vite's client waits for it
 * from a SharedWorker built on a blob URL, which the pages' Trusted Types policy
 * refuses: the client then gives up and never reloads the page, leaving a broken
 * one on screen. Without SharedWorker it polls from the page itself, over the
 * WebSocket the dev CSP already allows.
 */
export function devRestartPolling(): Plugin {
  return {
    name: 'dev-restart-polling',
    apply: 'serve',
    transformIndexHtml: () => [{ tag: 'script', children: 'window.SharedWorker = undefined;', injectTo: 'head-prepend' }],
  };
}
