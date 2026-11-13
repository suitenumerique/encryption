import Fastify from 'fastify';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { publicAssetsPlugin } from '@encryption/src/server/plugins/public-assets';

describe('the maintenance tool download', () => {
  let cwd: string;

  beforeEach(() => {
    cwd = mkdtempSync(resolve(tmpdir(), 'public-assets-'));
    vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function get() {
    const app = Fastify();

    await app.register(publicAssetsPlugin);

    return app.inject({ method: 'GET', url: '/public-assets/maintenance-tool.html' });
  }

  it('is a download that a browser would neither render nor give the origin to', async () => {
    mkdirSync(resolve(cwd, 'dist/maintenance'), { recursive: true });
    writeFileSync(resolve(cwd, 'dist/maintenance/maintenance-tool.html'), '<!doctype html><title>tool</title>');

    const response = await get();

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe('<!doctype html><title>tool</title>');
    expect(response.headers['content-disposition']).toBe('attachment; filename="lasuite-encryption-maintenance-tool.html"');
    expect(response.headers['content-security-policy']).toBe("sandbox; default-src 'none'");
    expect(response.headers['x-robots-tag']).toBe('noindex, nofollow');
  });

  it('says how to build it when the image or checkout has no build', async () => {
    const response = await get();

    expect(response.statusCode).toBe(404);
    expect(response.body).toContain('npm run build:maintenance');
  });
});
