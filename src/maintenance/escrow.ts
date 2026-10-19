/**
 * Maintenance escrow tooling: what an operator runs, offline, against rows
 * exported from a product table (architecture.md, Appendix E).
 *
 * The vault side produces one `maintenanceKey` per resource (see
 * src/crypto/maintenance-escrow.ts); this module is the other half. It works on
 * plain rows (`id`, `maintenanceKey`, optionally `encryptedContent` and
 * `recipients`) so that a product export of any shape can be piped in, and it
 * never touches a database: reading and writing back is the product's job. The
 * CLI in cli.ts is a thin shell over these functions, which the tests exercise
 * end to end against the real vault operations.
 */
import { z } from 'zod';

import {
  type HybridPublicKey,
  type HybridSecretKey,
  base64ToUint8,
  decryptContent,
  encryptContent,
  encryptSymmetricKeyForUsers,
  generateSymmetricKey,
  importPublicKeyFromBase64,
  uint8ToBase64,
  unwrapMaintenanceKey,
  verifyKeyRegistration,
  wrapKeyForMaintenance,
} from '@encryption/src/crypto';
import { DOMAIN_CONTENT, DOMAIN_KEM_DOCUMENT_KEY } from '@encryption/src/shared/crypto-domains';
import { VaultError } from '@encryption/src/shared/vault-error';
import { type Client, createClient, createConfig } from '@encryption/src/ui/api/generated/client';
import { getApiPublicKeys } from '@encryption/src/ui/api/generated/sdk.gen';
import type { ClientOptions } from '@encryption/src/ui/api/generated/types.gen';

const base64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, 'expected base64');

// A recipient's active encryption key as the directory publishes it: the base64 wire
// key, and the version the product stores next to the copy wrapped for it, since
// decryption selects exactly that key.
const recipientKeySchema = z.object({
  publicKey: base64,
  version: z.number().int().positive(),
});

export type RecipientKey = z.infer<typeof recipientKeySchema>;

// One product row. `recipients` is either the keys themselves (sub -> recipient key,
// e.g. from `fetch-public-keys`) or the subs to resolve against a registry.
export const maintenanceRowSchema = z.object({
  id: z.string().optional(),
  maintenanceKey: base64,
  encryptedContent: base64.optional(),
  recipients: z.union([z.record(z.string(), recipientKeySchema), z.array(z.string())]).optional(),
});

export type MaintenanceRow = z.infer<typeof maintenanceRowSchema>;

export function parseRow(entry: unknown, index: number): MaintenanceRow {
  const parsed = maintenanceRowSchema.safeParse(entry);

  if (!parsed.success) {
    throw new Error(`row ${index + 1}: ${z.prettifyError(parsed.error)}`);
  }

  return parsed.data;
}

/**
 * Accepts the two shapes an export naturally comes in: one JSON object per line
 * (`psql -At`, `jq -c`), or a JSON array (a REST listing such as the demo
 * store's). For an export too large to hold in memory, see `readRows` in io.ts,
 * which streams the first shape.
 */
export function parseRows(text: string): MaintenanceRow[] {
  const trimmed = text.trim();

  if (trimmed === '') return [];

  const raw: unknown[] = trimmed.startsWith('[')
    ? (JSON.parse(trimmed) as unknown[])
    : trimmed.split('\n').map((line) => JSON.parse(line) as unknown);

  return raw.map(parseRow);
}

/** A failed row's reason, led by the stable code when there is one (libsodium's own messages are not). */
export function describeError(error: unknown): string {
  if (error instanceof VaultError) return `${error.code}: ${error.message}`;

  return error instanceof Error ? error.message : String(error);
}

function label(row: MaintenanceRow, index: number): string {
  return row.id ?? `#${index + 1}`;
}

/** Unwrap a row's escrow copy; the resource key stays in memory, never in the output. */
export async function resolveRowKey(secretKey: HybridSecretKey, row: MaintenanceRow): Promise<Uint8Array> {
  return unwrapMaintenanceKey(secretKey, base64ToUint8(row.maintenanceKey));
}

export interface CheckResult {
  id: string;
  ok: boolean;
  error?: string;
}

/**
 * Coverage audit: does each escrow copy open with this key? Reports, never
 * throws, so one corrupt row does not hide the others. Prints no key material.
 */
export async function checkRows(secretKey: HybridSecretKey, rows: MaintenanceRow[]): Promise<CheckResult[]> {
  return Promise.all(
    rows.map(async (row, index) => {
      try {
        await resolveRowKey(secretKey, row);

        return { id: label(row, index), ok: true };
      } catch (error) {
        return { id: label(row, index), ok: false, error: describeError(error) };
      }
    })
  );
}

export interface DecryptResult {
  id: string;
  plaintext: string;
}

export async function decryptRow(secretKey: HybridSecretKey, row: MaintenanceRow, encoding: 'base64' | 'utf8', index = 0): Promise<DecryptResult> {
  if (!row.encryptedContent) {
    throw new Error(`row ${label(row, index)}: encryptedContent is required to decrypt`);
  }

  const key = await resolveRowKey(secretKey, row);
  const plaintext = await decryptContent(base64ToUint8(row.encryptedContent), key, DOMAIN_CONTENT);

  return { id: label(row, index), plaintext: encoding === 'utf8' ? new TextDecoder().decode(plaintext) : uint8ToBase64(plaintext) };
}

export interface RewrapOptions {
  /** The key the fresh escrow copy is wrapped for: the current one, or its successor during a key rotation. */
  maintenancePublicKey: HybridPublicKey;
  /** The recipients the resource key is (re)wrapped for, by sub. */
  recipients: Record<string, ResolvedRecipient>;
  /** Mint a new resource key and re-encrypt the content with it (needs `encryptedContent`). */
  rotateKey: boolean;
}

export interface ResolvedRecipient {
  publicKey: HybridPublicKey;
  version: number;
}

export interface RewrapResult {
  id: string;
  encryptedKeys: Record<string, string>;
  /** sub -> version of the encryption key its copy is wrapped to, to store with the copy. */
  keyVersions: Record<string, number>;
  maintenanceKey: string;
  encryptedContent?: string;
}

/**
 * Re-encode one resource without any user device. Two shapes of maintenance:
 *
 *   - `rotateKey: false`: the SAME resource key, wrapped again for `recipients`
 *     (a user whose wrapped copy is corrupt or whose encryption key rotated
 *     while they had no device to re-share from) and for the maintenance key.
 *   - `rotateKey: true`: a NEW resource key; the content is decrypted with the
 *     old one and re-encrypted, and every recipient plus the maintenance key get
 *     the new key. Old wrapped copies become useless, so the caller replaces the
 *     whole row.
 */
export async function rewrapRow(secretKey: HybridSecretKey, row: MaintenanceRow, options: RewrapOptions, index = 0): Promise<RewrapResult> {
  const id = label(row, index);
  const currentKey = await resolveRowKey(secretKey, row);

  let key = currentKey;
  let encryptedContent: string | undefined;

  if (options.rotateKey) {
    if (!row.encryptedContent) {
      throw new Error(`row ${id}: encryptedContent is required to rotate the key`);
    }

    const plaintext = await decryptContent(base64ToUint8(row.encryptedContent), currentKey, DOMAIN_CONTENT);
    key = await generateSymmetricKey();
    encryptedContent = uint8ToBase64(await encryptContent(plaintext, key, DOMAIN_CONTENT));
  }

  const recipients = Object.entries(options.recipients);
  const wrapped = await encryptSymmetricKeyForUsers(
    key,
    Object.fromEntries(recipients.map(([sub, recipient]) => [sub, recipient.publicKey])),
    DOMAIN_KEM_DOCUMENT_KEY
  );
  const encryptedKeys = Object.fromEntries(Object.entries(wrapped).map(([sub, blob]) => [sub, uint8ToBase64(blob)]));
  const keyVersions = Object.fromEntries(recipients.map(([sub, recipient]) => [sub, recipient.version]));
  const maintenanceKey = uint8ToBase64(await wrapKeyForMaintenance(key, options.maintenancePublicKey));

  return encryptedContent === undefined
    ? { id, encryptedKeys, keyVersions, maintenanceKey }
    : { id, encryptedKeys, keyVersions, maintenanceKey, encryptedContent };
}

/** The generated API client pointed at a deployment's vault origin, which serves the public directory. */
export function createRegistryClient(baseUrl: string): Client {
  return createClient(createConfig<ClientOptions>({ baseUrl: baseUrl.replace(/\/$/, ''), throwOnError: true }));
}

/**
 * Resolve subs to their active encryption keys through the public directory, with the
 * same binding verification the vault runs before it wraps (a record whose
 * signature does not verify is refused, never silently skipped). The out-of-band
 * fingerprint check has no equivalent here: the operator is trusting the
 * directory, which is acceptable for a maintenance operation on their own
 * deployment and is why this is a separate, explicit step.
 */
export async function fetchVerifiedPublicKeys(registry: Client, subs: string[]): Promise<Record<string, RecipientKey>> {
  const unique = [...new Set(subs)];

  if (unique.length === 0) return {};

  const { data, response } = await getApiPublicKeys({ client: registry, query: { subs: unique } });

  if (!data) {
    throw new Error(`registry answered ${response?.status ?? 'nothing'}`);
  }

  const resolved: Record<string, RecipientKey> = {};

  for (const entry of data.keys) {
    if (!entry.sub) continue;

    const verified = await verifyKeyRegistration({
      userId: entry.user_id,
      version: entry.version,
      createdAtMillis: entry.created_at_millis,
      encryptionPublicKeyB64: entry.encryption_public_key,
      signaturePublicKeyB64: entry.signature_public_key,
      keyBindingSignatureB64: entry.key_binding_signature,
    });

    if (!verified) {
      throw new Error(`registry record for ${entry.sub} fails its binding signature; refusing to wrap for it`);
    }

    resolved[entry.sub] = { publicKey: entry.encryption_public_key, version: entry.version };
  }

  const missing = unique.filter((sub) => !(sub in resolved));

  if (missing.length > 0) {
    throw new Error(`no active registration for: ${missing.join(', ')}`);
  }

  return resolved;
}

/** Turn a row's `recipients` into public keys, resolving subs through the registry when given as a list. */
export async function resolveRowRecipients(row: MaintenanceRow, registry: Client | undefined): Promise<Record<string, ResolvedRecipient>> {
  let keys: Record<string, RecipientKey>;

  if (Array.isArray(row.recipients)) {
    if (!registry) {
      throw new Error('recipients given as subs need --registry to resolve their public keys');
    }

    keys = await fetchVerifiedPublicKeys(registry, row.recipients);
  } else {
    keys = row.recipients ?? {};
  }

  return Object.fromEntries(
    Object.entries(keys).map(([sub, { publicKey, version }]) => [sub, { publicKey: importPublicKeyFromBase64(publicKey), version }])
  );
}
