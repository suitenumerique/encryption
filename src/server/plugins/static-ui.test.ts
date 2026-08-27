import fastifyStatic from '@fastify/static';
import Fastify from 'fastify';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isServableAsset } from '@encryption/src/server/plugins/static-ui';

jest.mock('@encryption/src/server/env', () => ({
  env: { UI_HOST: 'encryption.localhost:7200' },
}));

describe('isServableAsset', () => {
  it('serves the bundles and refuses the maps beside them', () => {
    expect(isServableAsset('/assets/interface-abc123.js')).toBe(true);
    expect(isServableAsset('/assets/interface-abc123.css')).toBe(true);
    expect(isServableAsset('/assets/inter-latin-wght-normal.woff2')).toBe(true);

    expect(isServableAsset('/assets/interface-abc123.js.map')).toBe(false);
    expect(isServableAsset('/assets/interface-abc123.css.map')).toBe(false);
  });

  it('is what @fastify/static actually applies', async () => {
    // The predicate is only worth anything wired in, and the wiring is one option
    // name away from silently serving everything again.
    const root = mkdtempSync(join(tmpdir(), 'assets-'));

    mkdirSync(join(root, 'assets'));
    writeFileSync(join(root, 'assets/interface-abc123.js'), 'console.log(1)');
    writeFileSync(join(root, 'assets/interface-abc123.js.map'), '{"version":3}');

    const app = Fastify();

    await app.register(fastifyStatic, {
      root: join(root, 'assets'),
      prefix: '/assets/',
      decorateReply: false,
      allowedPath: isServableAsset,
    });

    expect((await app.inject({ method: 'GET', url: '/assets/interface-abc123.js' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/assets/interface-abc123.js.map' })).statusCode).toBe(404);

    await app.close();
    rmSync(root, { recursive: true, force: true });
  });
});
