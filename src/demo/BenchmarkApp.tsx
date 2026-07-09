import { useCallback, useEffect, useRef, useState } from 'react';

import { VaultClient } from '@encryption/src/client/vault-client';
import { decryptContent, encryptContent, ensureSodium, generateSymmetricKey, readUint32LE, writeUint32LE } from '@encryption/src/crypto';
import { DEMO_USERS, getToken, loginUser } from '@encryption/src/demo/auth';
import { MSG_VAULT_COMMIT_STAGED, MSG_VAULT_GENERATE_KEYS, MSG_VAULT_RESULT } from '@encryption/src/shared/constants';

const VAULT_URL = 'http://data.encryption.localhost:7200';
const INTERFACE_URL = 'http://encryption.localhost:7200';

// libsodium WASM has limited heap (~256 MB). Data above this must be chunked.
const WASM_HEAP_LIMIT = 200 * 1024 * 1024;

const SIZE_PRESETS = [
  { label: '1 MB', bytes: 1 * 1024 * 1024 },
  { label: '10 MB', bytes: 10 * 1024 * 1024 },
  { label: '50 MB', bytes: 50 * 1024 * 1024 },
  { label: '100 MB', bytes: 100 * 1024 * 1024 },
  { label: '500 MB', bytes: 500 * 1024 * 1024 },
  { label: '1 GB', bytes: 1024 * 1024 * 1024 },
];

const CHUNK_PRESETS = [
  { label: 'None', bytes: null },
  { label: '1 MB', bytes: 1 * 1024 * 1024 },
  { label: '10 MB', bytes: 10 * 1024 * 1024 },
  { label: '50 MB', bytes: 50 * 1024 * 1024 },
  { label: '100 MB', bytes: 100 * 1024 * 1024 },
];

/**
 * Encrypt large data in chunks.
 * Format: [4-byte chunk count][for each chunk: 4-byte encrypted chunk length + encrypted chunk data]
 * Each chunk is independently encrypted with the same key (each gets its own random nonce).
 */
async function encryptChunked(data: Uint8Array, key: Uint8Array, chunkSize: number): Promise<Uint8Array> {
  if (data.length <= chunkSize) {
    return encryptContent(data, key);
  }

  const chunkCount = Math.ceil(data.length / chunkSize);
  const encryptedChunks: Uint8Array[] = [];
  let totalLen = 4; // 4 bytes for chunk count header

  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, data.length);
    const chunk = data.subarray(start, end);
    const encrypted = await encryptContent(chunk, key);
    encryptedChunks.push(encrypted);
    totalLen += 4 + encrypted.length; // 4 bytes length prefix + encrypted data
  }

  const result = new Uint8Array(totalLen);
  result.set(writeUint32LE(chunkCount), 0);
  let offset = 4;

  for (const chunk of encryptedChunks) {
    result.set(writeUint32LE(chunk.length), offset);
    offset += 4;
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

/**
 * Decrypt chunked data produced by encryptChunked.
 */
async function decryptChunked(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  // If data doesn't start with a valid chunk header, it's a single-chunk encryption
  // Heuristic: single-chunk data starts with a 24-byte nonce, not a small chunk count
  const possibleChunkCount = readUint32LE(data.subarray(0, 4));

  if (possibleChunkCount === 0 || possibleChunkCount > 1000) {
    // Not chunked — decrypt as single block
    return decryptContent(data, key);
  }

  const chunkCount = possibleChunkCount;
  const decryptedChunks: Uint8Array[] = [];
  let totalLen = 0;
  let offset = 4;

  for (let i = 0; i < chunkCount; i++) {
    const chunkLen = readUint32LE(data.subarray(offset, offset + 4));
    offset += 4;
    const chunk = data.subarray(offset, offset + chunkLen);
    const decrypted = await decryptContent(chunk, key);
    decryptedChunks.push(decrypted);
    totalLen += decrypted.length;
    offset += chunkLen;
  }

  const result = new Uint8Array(totalLen);
  let pos = 0;

  for (const chunk of decryptedChunks) {
    result.set(chunk, pos);
    pos += chunk.length;
  }

  return result;
}

interface BenchmarkResult {
  label: string;
  encryptMs: number;
  decryptMs: number;
  totalMs: number;
  sizeBytes: number;
  throughputMBs: number;
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
}

/**
 * Send a privileged request directly to the vault iframe.
 * In dev mode, the vault allows product origins to send privileged operations.
 */
function sendVaultRequest(vaultIframe: HTMLIFrameElement, type: string, suiteUserId: string, payload?: Record<string, unknown>): Promise<unknown> {
  const requestId = crypto.randomUUID();
  const origin = new URL(VAULT_URL).origin;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      window.removeEventListener('message', handler);
      reject(new Error('Request timed out'));
    }, 30000);

    function handler(event: MessageEvent) {
      if (event.origin !== origin) return;
      const data = event.data as { type?: string; requestId?: string; success?: boolean; data?: unknown; error?: string };
      if (data?.type !== MSG_VAULT_RESULT || data.requestId !== requestId) return;

      clearTimeout(timeout);
      window.removeEventListener('message', handler);

      if (data.success) resolve(data.data);
      else reject(new Error(data.error));
    }

    window.addEventListener('message', handler);
    vaultIframe.contentWindow!.postMessage({ type, requestId, suiteUserId, ...(payload ? { payload } : {}) }, origin);
  });
}

export function BenchmarkApp() {
  const clientRef = useRef<VaultClient | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [state, setState] = useState<'init' | 'login' | 'ready' | 'running' | 'done'>('init');
  const [results, setResults] = useState<BenchmarkResult[]>([]);
  const [selectedSize, setSelectedSize] = useState(SIZE_PRESETS[0].bytes);
  const [selectedChunkSize, setSelectedChunkSize] = useState<number | null>(null);
  const [progress, setProgress] = useState('');

  const log = useCallback((msg: string) => {
    const line = `[${new Date().toLocaleTimeString()}] ${msg}`;
    setLogs((prev) => [...prev, line]);
    console.log(line);
  }, []);

  // Initialize VaultClient
  useEffect(() => {
    const client = new VaultClient({ vaultUrl: VAULT_URL, interfaceUrl: INTERFACE_URL, theme: 'light' });
    clientRef.current = client;

    client.on('vault:ready', () => log('Vault iframe ready'));
    client.on('error', (err) => log(`Error: ${err.message}`));

    client
      .init()
      .then(() => {
        log('VaultClient initialized');
        setState('login');
      })
      .catch((err) => log(`Init failed: ${(err as Error).message}`));

    return () => client.destroy();
  }, [log]);

  // Login alice and generate keys if needed (no OIDC redirect — dev mode only)
  const handleLogin = useCallback(async () => {
    const client = clientRef.current;
    if (!client) return;

    const user = DEMO_USERS[0]; // alice
    log(`Logging in ${user.firstName}...`);

    try {
      const entry = await loginUser(user.username);
      log(`Authenticated as ${user.firstName} (sub: ${entry.userId.slice(0, 8)}...)`);
      client.setAuthContext({ suiteUserId: entry.userId });

      const { hasKeys } = await client.hasKeys();
      if (hasKeys) {
        setState('ready');
        log('Keys already exist — ready to benchmark');
      } else {
        log('No keys found — generating keys directly (dev mode)...');

        // In dev mode, the vault allows product origins to send generate-keys
        const vaultIframe = document.querySelector('iframe[title="Encryption Vault"]') as HTMLIFrameElement;
        if (!vaultIframe) {
          log('ERROR: Vault iframe not found');
          return;
        }

        // generate-keys only STAGES the vault in memory (the real onboarding
        // registers it before committing). This benchmark has no server step, so
        // commit it straight away to get a persisted vault the benchmark can reuse.
        await sendVaultRequest(vaultIframe, MSG_VAULT_GENERATE_KEYS, entry.userId);
        await sendVaultRequest(vaultIframe, MSG_VAULT_COMMIT_STAGED, entry.userId);
        log('Keys generated successfully');
        setState('ready');
      }
    } catch (err) {
      log(`Failed: ${(err as Error).message}`);
    }
  }, [log]);

  // Generate fake data
  const generateData = useCallback(
    (sizeBytes: number): Uint8Array => {
      log(`Generating ${formatSize(sizeBytes)} of random data...`);
      const data = new Uint8Array(sizeBytes);
      // Fill in chunks to avoid blocking (crypto.getRandomValues has a 64KB limit)
      const chunkSize = 65536;
      for (let offset = 0; offset < sizeBytes; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, sizeBytes);
        crypto.getRandomValues(data.subarray(offset, end));
      }
      log(`Data generated: ${formatSize(sizeBytes)}`);
      return data;
    },
    [log]
  );

  // Run the benchmark
  const runBenchmark = useCallback(async () => {
    const client = clientRef.current;
    if (!client) return;

    setState('running');
    setResults([]);

    const sizeBytes = selectedSize;
    log(`\n========== BENCHMARK START: ${formatSize(sizeBytes)} ==========`);

    try {
      // 1. Generate test data
      setProgress('Generating test data...');
      const testData = generateData(sizeBytes);

      // Small delay to let UI update
      await new Promise((r) => setTimeout(r, 50));

      // =====================================================
      // 2. DIRECT: encrypt/decrypt using crypto functions
      // =====================================================
      setProgress('Running DIRECT benchmark (no postMessage)...');
      log('--- Direct (in-page crypto, no postMessage) ---');

      await ensureSodium();
      const directKey = await generateSymmetricKey();

      // Warm up the in-page libsodium WASM with a small encrypt/decrypt cycle
      // so JIT compilation doesn't skew the benchmark
      const warmupDirect = new Uint8Array(1024);
      crypto.getRandomValues(warmupDirect);
      const warmupEnc = await encryptContent(warmupDirect, directKey);
      await decryptContent(warmupEnc, directKey);
      log('Direct crypto warmed up');

      await new Promise((r) => setTimeout(r, 50));

      // Determine effective chunk size:
      // - If user selected a chunk size, use it
      // - If "None" but data exceeds WASM heap limit, force 200 MB chunks to avoid _malloc crash
      // - If "None" and data fits, no chunking
      let effectiveChunkSize: number;
      let useChunking: boolean;

      if (selectedChunkSize !== null) {
        effectiveChunkSize = selectedChunkSize;
        useChunking = true;
      } else if (sizeBytes > WASM_HEAP_LIMIT) {
        effectiveChunkSize = WASM_HEAP_LIMIT;
        useChunking = true;
        log(`Data exceeds WASM heap limit — forcing ${formatSize(WASM_HEAP_LIMIT)} chunks to avoid _malloc crash`);
      } else {
        effectiveChunkSize = sizeBytes; // no chunking
        useChunking = false;
      }

      if (useChunking) {
        log(`Chunked encryption: ${Math.ceil(sizeBytes / effectiveChunkSize)} chunks of ${formatSize(effectiveChunkSize)}`);
      }

      const directEncStart = performance.now();
      const directEncrypted = await encryptChunked(testData, directKey, effectiveChunkSize);
      const directEncEnd = performance.now();
      const directEncMs = directEncEnd - directEncStart;
      log(`Direct encrypt: ${formatMs(directEncMs)} (${formatSize(directEncrypted.length)} ciphertext)`);

      await new Promise((r) => setTimeout(r, 50));

      const directDecStart = performance.now();
      const directDecrypted = useChunking ? await decryptChunked(directEncrypted, directKey) : await decryptContent(directEncrypted, directKey);
      const directDecEnd = performance.now();
      const directDecMs = directDecEnd - directDecStart;
      log(`Direct decrypt: ${formatMs(directDecMs)} (${formatSize(directDecrypted.length)} plaintext)`);

      // Verify correctness
      if (directDecrypted.length !== testData.length) {
        log('ERROR: Direct decryption size mismatch!');
      }

      const directResult: BenchmarkResult = {
        label: useChunking
          ? `Direct (${Math.ceil(sizeBytes / effectiveChunkSize)} chunks of ${formatSize(effectiveChunkSize)})`
          : 'Direct (no chunking)',
        encryptMs: directEncMs,
        decryptMs: directDecMs,
        totalMs: directEncMs + directDecMs,
        sizeBytes,
        throughputMBs: sizeBytes / (1024 * 1024) / ((directEncMs + directDecMs) / 1000),
      };

      setResults((prev) => [...prev, directResult]);
      await new Promise((r) => setTimeout(r, 50));

      // =====================================================
      // 3. VIA POSTMESSAGE: encrypt/decrypt through vault iframe
      // =====================================================
      setProgress('Running POSTMESSAGE benchmark (via vault iframe)...');
      log('--- Via PostMessage (VaultClient → vault iframe) ---');

      const tokenEntry = getToken(DEMO_USERS[0].username);
      if (!tokenEntry) {
        log('ERROR: Not authenticated');
        setState('ready');
        return;
      }

      log('Creating initial encrypted key...');

      // Create an encrypted symmetric key (one-time setup, not timed as part of the benchmark).
      // The vault resolves the recipient key from the directory (own identity is always trusted).
      const setupData = new Uint8Array(16); // tiny payload just to get the key
      crypto.getRandomValues(setupData);
      const selfLabel = { email: DEMO_USERS[0].email, name: `${DEMO_USERS[0].firstName} ${DEMO_USERS[0].lastName}` };
      const { encryptedKeys } = await client.encryptWithoutKey(setupData.buffer as ArrayBuffer, { [tokenEntry.userId]: selfLabel });
      const encryptedSymKey = encryptedKeys[tokenEntry.userId];
      log('Encrypted symmetric key obtained (setup done)');

      // Warm up the symmetric key cache in the vault by doing one encrypt
      const warmupData = new Uint8Array(16);
      crypto.getRandomValues(warmupData);
      await client.encryptWithKey(warmupData.buffer as ArrayBuffer, encryptedSymKey);
      log('Symmetric key cache warmed up');

      await new Promise((r) => setTimeout(r, 50));

      // For large data, chunk the postMessage calls too (vault has same WASM limits)
      let pmEncMs: number;
      let pmDecMs: number;
      let pmEncryptedSize: number;
      let pmDecryptedSize: number;

      if (useChunking) {
        const chunkCount = Math.ceil(sizeBytes / effectiveChunkSize);

        // Encrypt chunks via postMessage
        const pmEncStart = performance.now();
        const encryptedChunks: ArrayBuffer[] = [];

        for (let i = 0; i < chunkCount; i++) {
          const start = i * effectiveChunkSize;
          const end = Math.min(start + effectiveChunkSize, sizeBytes);
          const chunk = testData.slice(start, end);
          const { encryptedData } = await client.encryptWithKey(chunk.buffer as ArrayBuffer, encryptedSymKey);
          encryptedChunks.push(encryptedData);
        }

        const pmEncEnd = performance.now();
        pmEncMs = pmEncEnd - pmEncStart;
        pmEncryptedSize = encryptedChunks.reduce((sum, c) => sum + c.byteLength, 0);
        log(`PostMessage encrypt: ${formatMs(pmEncMs)} (${formatSize(pmEncryptedSize)} ciphertext, ${chunkCount} chunks)`);

        await new Promise((r) => setTimeout(r, 50));

        // Decrypt chunks via postMessage
        const pmDecStart = performance.now();
        let decTotal = 0;

        for (const chunk of encryptedChunks) {
          const { data } = await client.decryptWithKey(chunk, encryptedSymKey);
          decTotal += data.byteLength;
        }

        const pmDecEnd = performance.now();
        pmDecMs = pmDecEnd - pmDecStart;
        pmDecryptedSize = decTotal;
        log(`PostMessage decrypt: ${formatMs(pmDecMs)} (${formatSize(pmDecryptedSize)} plaintext, ${chunkCount} chunks)`);
      } else {
        // Single-shot for data that fits in WASM heap
        // We need a fresh copy of testData because ArrayBuffer gets transferred (neutered)
        const testDataForPostMessage = new Uint8Array(sizeBytes);
        testDataForPostMessage.set(testData);

        const pmEncStart = performance.now();
        const { encryptedData: pmEncrypted } = await client.encryptWithKey(testDataForPostMessage.buffer as ArrayBuffer, encryptedSymKey);
        const pmEncEnd = performance.now();
        pmEncMs = pmEncEnd - pmEncStart;
        pmEncryptedSize = pmEncrypted.byteLength;
        log(`PostMessage encrypt: ${formatMs(pmEncMs)} (${formatSize(pmEncryptedSize)} ciphertext)`);

        await new Promise((r) => setTimeout(r, 50));

        const pmDecStart = performance.now();
        const { data: pmDecrypted } = await client.decryptWithKey(pmEncrypted, encryptedSymKey);
        const pmDecEnd = performance.now();
        pmDecMs = pmDecEnd - pmDecStart;
        pmDecryptedSize = pmDecrypted.byteLength;
        log(`PostMessage decrypt: ${formatMs(pmDecMs)} (${formatSize(pmDecryptedSize)} plaintext)`);
      }

      const pmResult: BenchmarkResult = {
        label: useChunking
          ? `PostMessage (${Math.ceil(sizeBytes / effectiveChunkSize)} chunks of ${formatSize(effectiveChunkSize)})`
          : 'PostMessage (no chunking)',
        encryptMs: pmEncMs,
        decryptMs: pmDecMs,
        totalMs: pmEncMs + pmDecMs,
        sizeBytes,
        throughputMBs: sizeBytes / (1024 * 1024) / ((pmEncMs + pmDecMs) / 1000),
      };

      setResults((prev) => [...prev, pmResult]);

      // =====================================================
      // 4. Summary
      // =====================================================
      const overhead = pmResult.totalMs - directResult.totalMs;
      const overheadPct = ((overhead / directResult.totalMs) * 100).toFixed(1);
      log(`\n========== RESULTS ==========`);
      log(`Direct total:      ${formatMs(directResult.totalMs)}`);
      log(`PostMessage total:  ${formatMs(pmResult.totalMs)}`);
      log(`Overhead:           ${formatMs(overhead)} (+${overheadPct}%)`);
      log(`Direct throughput:  ${directResult.throughputMBs.toFixed(1)} MB/s`);
      log(`PM throughput:      ${pmResult.throughputMBs.toFixed(1)} MB/s`);
      log(`=============================\n`);

      setProgress('');
      setState('done');
    } catch (err) {
      const msg =
        err instanceof Error
          ? err.message
          : typeof err === 'object' && err !== null && 'message' in err
            ? String((err as { message: unknown }).message)
            : String(err);
      log(`ERROR: ${msg}`);
      setProgress('');
      setState('ready');
    }
  }, [selectedSize, selectedChunkSize, generateData, log]);

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 1100, margin: '0 auto', padding: 24 }}>
      <header style={{ borderBottom: '2px solid #000091', paddingBottom: 16, marginBottom: 24 }}>
        <h1 style={{ color: '#000091', margin: 0 }}>Encryption Benchmark</h1>
        <p style={{ color: '#666', margin: '4px 0 0', fontSize: 13 }}>
          Compare encryption performance: direct in-page crypto vs. postMessage through vault iframe. Measures the real overhead of the iframe
          isolation architecture.
        </p>
      </header>

      {/* Step 1: Login */}
      {state === 'login' && (
        <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8, marginBottom: 16 }}>
          <h3 style={{ margin: '0 0 8px' }}>Step 1: Login & Setup</h3>
          <p style={{ fontSize: 13, color: '#666' }}>
            Login as Alice. If no keys exist, they will be generated directly in the vault (dev mode — no OIDC needed).
          </p>
          <button onClick={handleLogin} style={{ padding: '8px 16px', cursor: 'pointer', fontSize: 14 }}>
            Login as Alice
          </button>
        </section>
      )}

      {/* Benchmark controls */}
      {(state === 'ready' || state === 'running' || state === 'done') && (
        <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8, marginBottom: 16 }}>
          <h3 style={{ margin: '0 0 12px' }}>Benchmark Configuration</h3>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Data size:</span>
            {SIZE_PRESETS.map((preset) => (
              <button
                key={preset.bytes}
                onClick={() => setSelectedSize(preset.bytes)}
                disabled={state === 'running'}
                style={{
                  padding: '4px 12px',
                  cursor: state === 'running' ? 'not-allowed' : 'pointer',
                  fontSize: 13,
                  border: selectedSize === preset.bytes ? '2px solid #000091' : '1px solid #ccc',
                  borderRadius: 4,
                  background: selectedSize === preset.bytes ? '#f0f0ff' : 'white',
                  fontWeight: selectedSize === preset.bytes ? 700 : 400,
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Chunk size:</span>
            {CHUNK_PRESETS.map((preset) => {
              const isSelected = selectedChunkSize === preset.bytes;
              const isDisabled = state === 'running' || (preset.bytes !== null && preset.bytes >= selectedSize);

              return (
                <button
                  key={preset.label}
                  onClick={() => setSelectedChunkSize(preset.bytes)}
                  disabled={isDisabled}
                  style={{
                    padding: '4px 12px',
                    cursor: isDisabled ? 'not-allowed' : 'pointer',
                    fontSize: 13,
                    border: isSelected ? '2px solid #000091' : '1px solid #ccc',
                    borderRadius: 4,
                    background: isDisabled && !isSelected ? '#f5f5f5' : isSelected ? '#f0f0ff' : 'white',
                    fontWeight: isSelected ? 700 : 400,
                    opacity: isDisabled && !isSelected ? 0.5 : 1,
                  }}
                >
                  {preset.label}
                </button>
              );
            })}
            <span style={{ fontSize: 11, color: '#999' }}>
              {selectedChunkSize === null
                ? selectedSize > WASM_HEAP_LIMIT
                  ? `(auto: ${formatSize(WASM_HEAP_LIMIT)} — required for WASM heap)`
                  : '(single block)'
                : `(${Math.ceil(selectedSize / selectedChunkSize)} chunks)`}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <button
              onClick={runBenchmark}
              disabled={state === 'running'}
              style={{
                padding: '8px 24px',
                cursor: state === 'running' ? 'not-allowed' : 'pointer',
                fontSize: 14,
                fontWeight: 600,
                background: state === 'running' ? '#ccc' : '#000091',
                color: 'white',
                border: 'none',
                borderRadius: 4,
              }}
            >
              {state === 'running' ? 'Running...' : 'Run Benchmark'}
            </button>
            {progress && <span style={{ fontSize: 13, color: '#666', fontStyle: 'italic' }}>{progress}</span>}
          </div>
        </section>
      )}

      {/* Results table */}
      {results.length > 0 && (
        <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8, marginBottom: 16 }}>
          <h3 style={{ margin: '0 0 12px' }}>Results — {formatSize(results[0].sizeBytes)}</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #000091' }}>
                <th style={{ textAlign: 'left', padding: 8 }}>Method</th>
                <th style={{ textAlign: 'right', padding: 8 }}>Encrypt</th>
                <th style={{ textAlign: 'right', padding: 8 }}>Decrypt</th>
                <th style={{ textAlign: 'right', padding: 8 }}>Total</th>
                <th style={{ textAlign: 'right', padding: 8 }}>Throughput</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #eee' }}>
                  <td style={{ padding: 8, fontWeight: 600 }}>{r.label}</td>
                  <td style={{ padding: 8, textAlign: 'right', fontFamily: 'monospace' }}>{formatMs(r.encryptMs)}</td>
                  <td style={{ padding: 8, textAlign: 'right', fontFamily: 'monospace' }}>{formatMs(r.decryptMs)}</td>
                  <td style={{ padding: 8, textAlign: 'right', fontFamily: 'monospace', fontWeight: 600 }}>{formatMs(r.totalMs)}</td>
                  <td style={{ padding: 8, textAlign: 'right', fontFamily: 'monospace' }}>{r.throughputMBs.toFixed(1)} MB/s</td>
                </tr>
              ))}
            </tbody>
          </table>
          {results.length === 2 && (
            <div
              style={{
                marginTop: 16,
                padding: 12,
                background: '#f0f0ff',
                borderRadius: 4,
                fontSize: 14,
              }}
            >
              <strong>PostMessage overhead:</strong> {formatMs(results[1].totalMs - results[0].totalMs)} (+
              {(((results[1].totalMs - results[0].totalMs) / results[0].totalMs) * 100).toFixed(1)}%)
              <br />
              <span style={{ fontSize: 12, color: '#666' }}>
                Encrypt overhead: {formatMs(results[1].encryptMs - results[0].encryptMs)} | Decrypt overhead:{' '}
                {formatMs(results[1].decryptMs - results[0].decryptMs)}
              </span>
            </div>
          )}
        </section>
      )}

      {/* Logs */}
      <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <h3 style={{ margin: 0 }}>Log</h3>
          <button onClick={() => setLogs([])} style={{ padding: '2px 8px', fontSize: 12, cursor: 'pointer' }}>
            Clear
          </button>
        </div>
        <div
          style={{
            fontFamily: 'monospace',
            fontSize: 12,
            background: '#1e1e1e',
            color: '#d4d4d4',
            padding: 12,
            borderRadius: 4,
            maxHeight: 400,
            overflowY: 'auto',
            minHeight: 100,
            whiteSpace: 'pre-wrap',
          }}
        >
          {logs.length === 0 ? (
            <span style={{ color: '#666' }}>Waiting...</span>
          ) : (
            logs.map((line, i) => (
              <div key={i} style={{ marginBottom: 2 }}>
                {line}
              </div>
            ))
          )}
        </div>
      </section>

      <footer style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid #ddd', fontSize: 12, color: '#999' }}>
        This benchmark measures the overhead of postMessage + structured clone transfer for large ArrayBuffers through the vault iframe, compared to
        running the same XChaCha20-Poly1305 operations directly in the page. The symmetric key cache is warmed before timing, so only the data
        transfer + crypto cost is measured.
      </footer>
    </div>
  );
}
