/**
 * `npm run maintenance -- <command>`: the operator side of the maintenance escrow
 * (architecture.md, Appendix C). Rows are read from `--in <file>` or stdin (one
 * JSON object per line, streamed, or a JSON array), results are written to
 * `--out <file>` or stdout, one JSON object per line. Nothing here reads a
 * database: exporting rows and writing results back is the product's SQL.
 *
 * The secret key file is read from disk on every command and never printed;
 * `decrypt` is the only command whose output is plaintext.
 */
import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';

import { generateMaintenanceKeyPair, parseMaintenanceKeyPair, parseMaintenancePublicKey, serializeMaintenanceKeyPair } from '@encryption/src/crypto';
import {
  type MaintenanceRow,
  checkRows,
  createRegistryClient,
  decryptRow,
  fetchVerifiedPublicKeys,
  resolveRowRecipients,
  rewrapRow,
} from '@encryption/src/maintenance/escrow';
import { closeOutput, openInput, openOutput, readRows, writeResult } from '@encryption/src/maintenance/io';

interface StreamOptions {
  in?: string;
  out?: string;
}

function loadKeyPair(path: string) {
  return parseMaintenanceKeyPair(readFileSync(path, 'utf8'));
}

/**
 * Per-row failures are reported in the result stream and turned into a non-zero
 * exit at the end, so a batch of a thousand rows neither stops at the first bad
 * one nor pretends to have succeeded. `failed` lets a command whose result is
 * itself a verdict (`check`) count a row without throwing.
 */
async function forEachRow<T>(
  options: StreamOptions,
  work: (row: MaintenanceRow, index: number) => Promise<T>,
  failed?: (result: T) => boolean
): Promise<void> {
  const output = openOutput(options.out);
  let total = 0;
  let failures = 0;

  for await (const row of readRows(openInput(options.in))) {
    const index = total;
    total += 1;

    try {
      const result = await work(row, index);

      if (failed?.(result)) failures += 1;
      writeResult(output, result);
    } catch (error) {
      failures += 1;
      writeResult(output, { id: row.id ?? `#${index + 1}`, error: error instanceof Error ? error.message : String(error) });
    }
  }

  await closeOutput(output);
  process.stderr.write(`${total - failures} of ${total} row(s) succeeded${options.out ? `, results in ${options.out}` : ''}\n`);

  if (failures > 0) process.exitCode = 1;
}

/** Every command that works on rows takes the same two options. */
function rowCommand(name: string): Command {
  return program
    .command(name)
    .option('--in <file>', 'read the rows from this file instead of stdin')
    .option('--out <file>', 'write the results to this file (owner-readable only) instead of stdout');
}

const program = new Command();

program.name('maintenance').description('Operate the maintenance escrow of an encryption deployment (architecture.md, Appendix C).');

program
  .command('keygen')
  .description('Generate the operator key pair. Prints the public key to put in MAINTENANCE_ESCROW_PUBLIC_KEY; the file holds the secret key.')
  .requiredOption('--out <file>', 'where to write the key file (refuses to overwrite)')
  .action(async (options: { out: string }) => {
    const pair = await generateMaintenanceKeyPair();
    const file = serializeMaintenanceKeyPair(pair);

    writeFileSync(options.out, file, { flag: 'wx', mode: 0o600 });

    const { publicKey } = JSON.parse(file) as { publicKey: string };

    process.stderr.write(`Secret key written to ${options.out}. Keep it offline; MAINTENANCE_ESCROW_PUBLIC_KEY is the line below.\n`);
    process.stdout.write(`${publicKey}\n`);
  });

program
  .command('public-key')
  .description('Print the public key of a key file (the MAINTENANCE_ESCROW_PUBLIC_KEY value).')
  .requiredOption('--key <file>', 'the operator key file')
  .action((options: { key: string }) => {
    const { publicKey } = JSON.parse(readFileSync(options.key, 'utf8')) as { publicKey: string };

    parseMaintenancePublicKey(publicKey);
    process.stdout.write(`${publicKey}\n`);
  });

rowCommand('check')
  .description('Audit rows: does each maintenanceKey open with this key? Outputs {id, ok, error?} per row, no key material.')
  .requiredOption('--key <file>', 'the operator key file')
  .action(async (options: StreamOptions & { key: string }) => {
    const pair = loadKeyPair(options.key);

    await forEachRow(
      options,
      async (row, index) => ({ ...(await checkRows(pair.secretKey, [row]))[0], id: row.id ?? `#${index + 1}` }),
      (result) => !result.ok
    );
  });

rowCommand('decrypt')
  .description('Decrypt rows ({maintenanceKey, encryptedContent}). Outputs {id, plaintext} per row, base64 unless --utf8.')
  .requiredOption('--key <file>', 'the operator key file')
  .option('--utf8', 'decode the plaintext as UTF-8 text instead of base64', false)
  .action(async (options: StreamOptions & { key: string; utf8: boolean }) => {
    const pair = loadKeyPair(options.key);

    await forEachRow(options, (row, index) => decryptRow(pair.secretKey, row, options.utf8 ? 'utf8' : 'base64', index));
  });

rowCommand('rewrap')
  .description(
    'Re-encode rows for their `recipients` (sub -> public key, or subs with --registry) and a fresh maintenance copy. ' +
      'Outputs {id, encryptedKeys, maintenanceKey} per row, plus encryptedContent with --rotate-key.'
  )
  .requiredOption('--key <file>', 'the operator key file that opens the current maintenanceKey')
  .option('--next-public-key <base64>', 'wrap the new maintenance copy for this public key instead (maintenance key rotation)')
  .option('--registry <url>', 'the vault origin (https://data.encryption.example), to resolve recipients given as subs')
  .option('--rotate-key', 'mint a new resource key and re-encrypt encryptedContent with it', false)
  .action(async (options: StreamOptions & { key: string; nextPublicKey?: string; registry?: string; rotateKey: boolean }) => {
    const pair = loadKeyPair(options.key);
    const maintenancePublicKey = options.nextPublicKey ? parseMaintenancePublicKey(options.nextPublicKey) : pair.publicKey;
    const registry = options.registry ? createRegistryClient(options.registry) : undefined;

    await forEachRow(options, async (row, index) => {
      const recipients = await resolveRowRecipients(row, registry);

      return rewrapRow(pair.secretKey, row, { maintenancePublicKey, recipients, rotateKey: options.rotateKey }, index);
    });
  });

program
  .command('fetch-public-keys')
  .description('Resolve subs through the public directory, verifying each binding signature. Outputs one {sub, publicKey} per line.')
  .requiredOption('--registry <url>', 'the vault origin (https://data.encryption.example)')
  .argument('<subs...>', 'OIDC subs to resolve')
  .action(async (subs: string[], options: { registry: string }) => {
    const keys = await fetchVerifiedPublicKeys(createRegistryClient(options.registry), subs);

    for (const [sub, publicKey] of Object.entries(keys)) writeResult(process.stdout, { sub, publicKey });
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
