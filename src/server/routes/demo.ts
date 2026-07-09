import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ServerResponse } from 'http';

/**
 * DEV-ONLY store for the demo products. The demo apps run as several independent
 * origins (ports 7201/7202, plus any extra tabs, browsers or incognito windows).
 * A per-tab in-memory list could never show the same documents to two tabs of the
 * SAME product, which makes sharing/trust flows impossible to exercise. So the
 * Fastify process keeps a module-level store shared across every instance.
 *
 * The store is NAMESPACED PER PRODUCT (by the `product` query param, one per port),
 * mirroring the real suite where Docs and Drive are DIFFERENT products with their
 * own documents but the SAME encryption vault: a doc created on product A never
 * shows up on product B, yet the same user's keys work on both. User-to-user
 * sharing is exercised within one product by switching the active user.
 *
 * It holds ONLY ciphertext and sharing metadata, never plaintext. Resets on server
 * restart, and this route is registered only in development, never in production.
 */

interface SharedAccess {
  userId: string;
  fullName: string;
  email: string;
  publicKey: string | null;
  signaturePublicKey: string | null;
  role: string;
}

// Everything is opaque to the server. Field names match the demo client's shape
// verbatim; `product` is added server-side from the query, so the client's
// document shape is untouched.
interface DemoDocument {
  id: string;
  title: string;
  encryptedContent: string; // base64 ciphertext
  encryptedKeys: Record<string, string>; // userId -> base64 wrapped symmetric key
  createdBy: string; // demo username of the author
  createdAtMillis: number;
  sharedWith: SharedAccess[];
  product: string; // which demo product (origin/port) this doc belongs to
}

const documents = new Map<string, DemoDocument>();
// Each open SSE connection remembers which product it is watching, so a mutation
// on product A is pushed only to product A's instances.
const streams = new Map<ServerResponse, string>();

function productOf(request: FastifyRequest): string {
  const p = (request.query as { product?: string } | undefined)?.product;

  return typeof p === 'string' && p.length > 0 ? p : 'default';
}

// One product's documents, oldest first (stable order across instances).
function snapshot(product: string): DemoDocument[] {
  return [...documents.values()].filter((d) => d.product === product).sort((a, b) => a.createdAtMillis - b.createdAtMillis);
}

// Push a product's list to every instance watching THAT product. Dead
// connections are dropped on the first failed write.
function broadcast(product: string): void {
  const payload = `data: ${JSON.stringify(snapshot(product))}\n\n`;

  for (const [res, watched] of streams) {
    if (watched !== product) continue;

    try {
      res.write(payload);
    } catch {
      streams.delete(res);
    }
  }
}

export async function demoRoute(app: FastifyInstance) {
  // Live document list over Server-Sent Events, scoped to one product: the full
  // list is sent on connect and again after every mutation of that product.
  app.get('/api/demo/events', (request: FastifyRequest, reply: FastifyReply) => {
    const product = productOf(request);

    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no', // keep proxies from buffering the stream
    });
    reply.raw.write(`data: ${JSON.stringify(snapshot(product))}\n\n`);

    // Comment pings keep the connection alive through idle proxy timeouts.
    const heartbeat = setInterval(() => reply.raw.write(': ping\n\n'), 25000);
    streams.set(reply.raw, product);

    request.raw.on('close', () => {
      clearInterval(heartbeat);
      streams.delete(reply.raw);
    });
  });

  app.get('/api/demo/documents', async (request) => snapshot(productOf(request)));

  app.post<{ Body: DemoDocument }>('/api/demo/documents', async (request, reply) => {
    const product = productOf(request);
    const doc = { ...request.body, product };
    documents.set(doc.id, doc);
    broadcast(product);
    reply.code(201);

    return doc;
  });

  // Update sharing: the client re-wraps the document key for the new recipients
  // and sends the merged access list + wrapped-key map.
  app.put<{ Params: { id: string }; Body: { sharedWith: SharedAccess[]; encryptedKeys: Record<string, string> } }>(
    '/api/demo/documents/:id',
    async (request, reply) => {
      const existing = documents.get(request.params.id);

      if (!existing) {
        reply.code(404);

        return { error: 'not found' };
      }

      existing.sharedWith = request.body.sharedWith;
      existing.encryptedKeys = request.body.encryptedKeys;
      broadcast(existing.product);

      return existing;
    }
  );

  // Wipe one product's documents — convenient between test runs.
  app.delete('/api/demo/documents', async (request) => {
    const product = productOf(request);

    for (const [id, doc] of documents) {
      if (doc.product === product) documents.delete(id);
    }
    broadcast(product);

    return { ok: true };
  });
}
