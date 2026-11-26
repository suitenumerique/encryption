import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

// API answers are per user: no cache may keep one unless its route chose a policy.
// fastify-plugin so the hook runs for the routes registered outside this plugin.
export const apiCacheControlPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.addHook('onSend', async (request, reply, payload) => {
    if (request.url.startsWith('/api/') && !reply.hasHeader('Cache-Control')) {
      reply.header('Cache-Control', 'no-store');
    }

    return payload;
  });
});
