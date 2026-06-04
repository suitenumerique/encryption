import type { FastifyInstance } from 'fastify';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { env } from '@encryption/src/server/env';

/**
 * Build the runtime config script for the vault HTML.
 * Frozen and non-writable to prevent tampering.
 */
function buildVaultConfigScript(): string {
  const config = {
    allowedOrigins: env.ALLOWED_FRAME_ANCESTORS.split(',').map((s) => s.trim()),
    interfaceOrigin: env.UI_URL,
  };

  return `<script>Object.defineProperty(window,"__ENCRYPTION_VAULT_CONFIG__",{value:Object.freeze(${JSON.stringify(config)}),writable:false,enumerable:true,configurable:false});</script>`;
}

export async function staticVaultPlugin(app: FastifyInstance): Promise<void> {
  const vaultDir = resolve(process.cwd(), 'dist/vault');
  const clientDir = resolve(process.cwd(), 'dist/client');

  if (!existsSync(vaultDir)) {
    app.log.warn('Vault dist files not found - run "npm run build:vault" first');

    return;
  }

  const files = new Map<string, { content: string | Buffer; type: string }>();

  const vaultFiles: Record<string, { dir: string; filename: string; type: string }> = {
    '/bridge.html': { dir: 'vault', filename: 'bridge.html', type: 'text/html' },
    '/vault.js': { dir: 'vault', filename: 'vault.js', type: 'application/javascript' },
    '/sw.js': { dir: 'vault', filename: 'sw.js', type: 'application/javascript' },
    '/client.js': { dir: 'client', filename: 'client.js', type: 'application/javascript' },
    '/client.mjs': { dir: 'client', filename: 'client.mjs', type: 'application/javascript' },
    '/client.d.ts': { dir: 'client', filename: 'client.d.ts', type: 'text/plain' },
  };

  for (const [path, info] of Object.entries(vaultFiles)) {
    const baseDir = info.dir === 'vault' ? vaultDir : clientDir;
    const filePath = resolve(baseDir, info.filename);

    if (existsSync(filePath)) {
      if (path === '/bridge.html') {
        // Inject runtime config into the vault HTML
        const rawHtml = readFileSync(filePath, 'utf-8');
        const configScript = buildVaultConfigScript();
        files.set(path, { content: rawHtml.replace('</head>', `${configScript}\n</head>`), type: info.type });
      } else {
        files.set(path, { content: readFileSync(filePath), type: info.type });
      }
    }
  }

  app.addHook('onRequest', async (request, reply) => {
    if (request.hostname !== env.VAULT_HOST) {
      return;
    }

    const path = request.url.split('?')[0];
    const file = files.get(path);

    if (file) {
      reply.type(file.type).header('Access-Control-Allow-Origin', '*').send(file.content);
    }
  });
}
