import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import type { PutItemInput } from '@encryption/src/vault/operations/vault-sync';
import { createHttpSyncTransport } from '@encryption/src/vault/operations/vault-sync-transport';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

const SEALED: SealedItem = { id: 'tofu:bob', type: 'tofu', revisionDate: 42, ciphertext: 'CT' };

describe('http sync transport', () => {
  it('sends the JWT and maps the items response to a PulledVault', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = jest.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init });

      return jsonResponse({
        revision: 7,
        manifest: 'M',
        manifest_sig: 'S',
        items: [{ item_id: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revision_date_millis: 42 }],
      });
    }) as unknown as typeof fetch;

    const transport = createHttpSyncTransport({ token: 'tok', fetchImpl });
    const pulled = await transport.fetch();

    expect(pulled).toEqual({ sealed: [SEALED], manifest: 'M', manifestSig: 'S', revision: 7 });
    expect(calls[0].url).toContain('/api/vault/items');
    expect((calls[0].init?.headers as Record<string, string>).Authorization).toBe('Bearer tok');
  });

  it('treats a never-bootstrapped vault (revision 0) as no remote state', async () => {
    const fetchImpl = jest.fn(async () => jsonResponse({ revision: 0, manifest: null, manifest_sig: null, items: [] })) as unknown as typeof fetch;

    expect(await createHttpSyncTransport({ fetchImpl }).fetch()).toBeNull();
  });

  it('PUTs an item to its id route and returns the new revision', async () => {
    let putUrl = '';
    let putBody: Record<string, unknown> = {};
    const fetchImpl = jest.fn(async (url: string | URL | Request, init?: RequestInit) => {
      putUrl = String(url);
      putBody = JSON.parse(init!.body as string);

      return jsonResponse({ revision: 8 });
    }) as unknown as typeof fetch;

    const input: PutItemInput = { item: SEALED, lastKnownRevisionDate: 41, manifest: 'M2', manifestSig: 'S2', revision: 8 };
    const outcome = await createHttpSyncTransport({ token: 'tok', fetchImpl }).putItem(input);

    expect(outcome).toEqual({ ok: true, revision: 8 });
    expect(putUrl).toContain('/api/vault/items/tofu%3Abob');
    expect(putBody.item).toEqual({ item_id: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revision_date_millis: 42 });
    expect(putBody.last_known_revision_date_millis).toBe(41);
  });

  it('maps a 409 to a conflict outcome without throwing', async () => {
    const fetchImpl = jest.fn(async () => jsonResponse({ code: 'vault_item_out_of_date' }, 409)) as unknown as typeof fetch;

    const input: PutItemInput = { item: SEALED, lastKnownRevisionDate: null, manifest: 'M', manifestSig: 'S', revision: 2 };

    expect(await createHttpSyncTransport({ fetchImpl }).putItem(input)).toEqual({ ok: false, conflict: true });
  });
});
