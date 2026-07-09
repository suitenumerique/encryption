import { CunninghamProvider } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { VaultClient } from '@encryption/src/client/vault-client';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { ShareDocumentModal } from '@encryption/src/demo/ShareDocumentModal';
import {
  DEMO_USERS,
  type DemoUser,
  getKnownUserId,
  getToken,
  isLoggedIn,
  loginUser,
  logoutUser,
  resolveAllDemoUserIds,
} from '@encryption/src/demo/auth';
import { type RecipientLabel } from '@encryption/src/shared/schemas/interface-context';
import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';

type EncryptionState = 'loading' | 'no-keys' | 'ready' | 'error' | 'not-connected';

// How a product should react to the SDK's stable VaultError codes: map the ones
// that need user action to a prompt that opens the encryption UI, so the user
// learns WHY a document won't decrypt instead of seeing a bare failure. Transient
// or unrelated errors (timeout, wrong phrase) return null and don't raise a badge.
function attentionMessage(err: unknown): string | null {
  if (!isVaultError(err)) return null;

  switch (err.code) {
    case VaultErrorCode.VAULT_INTEGRITY_FAILED:
      return 'Your encrypted data failed an integrity check and may have been altered on the server. Open encryption to review.';
    case VaultErrorCode.MISSING_KEYS:
      return 'Encryption keys are missing on this device. Open encryption to restore or set them up.';
    case VaultErrorCode.UNTRUSTED_RECIPIENT:
      return "A recipient's identity is not verified. Open encryption settings to verify before sharing.";
    default:
      return null;
  }
}

const VAULT_URL = 'http://data.encryption.localhost:7200';
const INTERFACE_URL = 'http://encryption.localhost:7200';

interface SharedAccess {
  userId: string;
  fullName: string;
  email: string;
  publicKey: string | null;
  signaturePublicKey: string | null;
  role: string;
}

// Wire shape of a document in the shared demo store. Everything crossing to the
// server is base64 ciphertext or metadata — never plaintext. `encryptedKeys`
// maps each authorized userId to their own wrapped copy of the symmetric key,
// so a recipient in any other instance can decrypt for real.
interface FakeDocument {
  id: string;
  title: string;
  encryptedContent: string; // base64
  encryptedKeys: Record<string, string>; // userId -> base64 wrapped key
  createdBy: string;
  createdAtMillis: number;
  sharedWith: SharedAccess[];
}

const DEMO_API = '/api/demo/documents';
// Each demo port is a DIFFERENT product (like Docs vs Drive): the store is
// namespaced by this id, so documents created on one product never leak into the
// other, even though both share the same encryption vault.
const PRODUCT_ID = window.location.port || 'default';

// base64 <-> ArrayBuffer bridges for the crypto SDK, which speaks ArrayBuffer
// while the store speaks base64. Slice to an exact-sized buffer so no trailing
// bytes of a shared backing buffer leak in.
function abToBase64(buf: ArrayBuffer): string {
  return uint8ToBase64(new Uint8Array(buf));
}

function base64ToAb(s: string): ArrayBuffer {
  const u = base64ToUint8(s);

  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

export function DemoApp() {
  const clientRef = useRef<VaultClient | null>(null);
  const [state, setState] = useState<EncryptionState>('not-connected');
  const [currentUser, setCurrentUser] = useState<DemoUser | null>(null);
  const currentUserRef = useRef<DemoUser | null>(null);
  currentUserRef.current = currentUser;
  const [logs, setLogs] = useState<string[]>([]);
  const logsContainerRef = useRef<HTMLDivElement | null>(null);
  const [allDocuments, setAllDocuments] = useState<FakeDocument[]>([]);
  // Show documents owned by or shared with the current user
  const currentKeycloakId = currentUser ? getKnownUserId(currentUser.username) : null;
  const documents = useMemo(() => {
    if (!currentUser) return [];
    return allDocuments.filter((doc) => doc.createdBy === currentUser.username || doc.sharedWith.some((a) => a.userId === currentKeycloakId));
  }, [allDocuments, currentUser, currentKeycloakId]);
  const [newDocTitle, setNewDocTitle] = useState('');
  const [newDocContent, setNewDocContent] = useState('');
  const [interfaceContainer, setInterfaceContainer] = useState<HTMLDivElement | null>(null);
  const [shareDoc, setShareDoc] = useState<FakeDocument | null>(null);
  // A standing prompt raised when a vault operation fails with a code that needs
  // user action (integrity failure, missing keys, ...). Persists across the raw
  // per-doc errors so the user has a durable "open encryption" affordance.
  const [attention, setAttention] = useState<string | null>(null);

  // Force re-render when login state changes
  const [, setLoginVersion] = useState(0);
  const refreshLoginState = useCallback(() => setLoginVersion((v) => v + 1), []);

  const productName = window.location.port === '7202' ? 'Product B' : 'Product A';

  const log = useCallback((msg: string) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  }, []);

  // Keep the log panel pinned to the newest entry.
  useEffect(() => {
    const el = logsContainerRef.current;

    if (el) el.scrollTop = el.scrollHeight;
  }, [logs]);

  // Pre-resolve all demo users' Keycloak subs so the Share modal can look them up
  useEffect(() => {
    resolveAllDemoUserIds();
  }, []);

  // Subscribe to the shared demo store over SSE. The server pushes the full
  // document list on connect and after every change, so every demo instance
  // (this tab, the other port, a private window) converges on one list.
  useEffect(() => {
    const source = new EventSource(`${DEMO_API.replace('/documents', '/events')}?product=${PRODUCT_ID}`);

    source.onmessage = (event) => {
      try {
        setAllDocuments(JSON.parse(event.data) as FakeDocument[]);
      } catch {
        /* ignore malformed frames (e.g. heartbeat comments never reach onmessage) */
      }
    };

    return () => source.close();
  }, []);

  // Initialize vault client
  useEffect(() => {
    const client = new VaultClient({ vaultUrl: VAULT_URL, interfaceUrl: INTERFACE_URL, theme: 'light' });
    clientRef.current = client;

    client.on('vault:ready', () => {
      log('Vault ready');
      // Re-apply the auth context after ANY vault (re)initialization — a fresh
      // VaultClient (dev HMR, remount) starts with none, so operations would
      // otherwise fail with "auth context required". The userId comes from the
      // persistent map, so it works even if the short-lived token has expired.
      const user = currentUserRef.current;
      const suiteUserId = user ? getKnownUserId(user.username) : null;

      if (suiteUserId) client.setAuthContext({ suiteUserId });
    });
    client.on('onboarding:complete', ({ publicKey }) => {
      setState('ready');
      log(`Onboarding complete. Public key: ${publicKey.slice(0, 30)}...`);
    });
    client.on('interface:closed', () => {
      log('Interface closed');
      setInterfaceOpen(false);
      // Re-check key state after the interface closes (keys may have been created/deleted)
      client
        .hasKeys()
        .then(({ hasKeys: exists }) => {
          setState(exists ? 'ready' : 'no-keys');
        })
        .catch(() => {
          // Auth context may not be set yet — ignore
        });
    });
    client.on('error', (err) => log(`Error: ${err.message}`));
    client.on('keys-changed', () => {
      log('Keys changed (from another tab/device)');
      client
        .hasKeys()
        .then(({ hasKeys: exists }) => {
          setState(exists ? 'ready' : 'no-keys');
        })
        .catch(() => {});
    });
    client.on('keys-destroyed', () => {
      setState('no-keys');
      log('Keys destroyed (from another tab/device)');
    });

    client
      .init()
      .then(() => log('VaultClient initialized'))
      .catch((err) => log(`Init failed: ${(err as Error).message}`));

    return () => client.destroy();
  }, [log]);

  // Logout a user
  const handleLogout = useCallback(
    (user: DemoUser) => {
      logoutUser(user.username);
      log(`Logged out ${user.firstName}`);
      refreshLoginState();

      if (currentUser?.username === user.username) {
        setCurrentUser(null);
        setState('not-connected');
      }
    },
    [currentUser, log, refreshLoginState]
  );

  // Select a user as the active one. Logs in on demand (and re-logs in if the
  // short-lived token has expired), so the demo is a single "Select" click
  // instead of separate Login + Select steps.
  const handleSelectUser = useCallback(
    async (user: DemoUser) => {
      const client = clientRef.current;

      if (!client) return;

      let tokenEntry = getToken(user.username);

      if (!tokenEntry) {
        try {
          log(`Logging in ${user.firstName} ${user.lastName}...`);

          tokenEntry = await loginUser(user.username);

          refreshLoginState();
        } catch (err) {
          log(`Login failed for ${user.firstName}: ${(err as Error).message}`);

          return;
        }
      }

      // Close any open interface iframe before switching users
      client.closeInterface();
      setInterfaceOpen(false);

      setCurrentUser(user);
      setState('loading');
      log(`Switching to ${user.firstName} ${user.lastName}...`);

      client.setAuthContext({ suiteUserId: tokenEntry.userId });

      try {
        const { hasKeys } = await client.hasKeys();

        if (hasKeys) {
          setState('ready');
          log('Keys found in vault');
        } else {
          setState('no-keys');
          log('No keys — onboarding required');
        }
      } catch (err) {
        setState('error');
        log(`Error checking keys: ${(err as Error).message}`);
      }
    },
    [log, refreshLoginState]
  );

  const [interfaceOpen, setInterfaceOpen] = useState(false);

  const handleOpenOnboarding = useCallback(() => {
    if (!interfaceContainer || !clientRef.current) return;
    clientRef.current.openOnboarding(interfaceContainer);
    setInterfaceOpen(true);
    log('Opening onboarding interface...');
  }, [interfaceContainer, log]);

  const handleOpenSettings = useCallback(() => {
    if (!interfaceContainer || !clientRef.current) return;
    clientRef.current.openSettings(interfaceContainer);
    setInterfaceOpen(true);
    log('Opening settings...');
  }, [interfaceContainer, log]);

  const handleCreateDocument = useCallback(async () => {
    const client = clientRef.current;
    if (!client || !currentUser || !newDocTitle.trim() || !newDocContent.trim()) return;

    try {
      const plainBytes = new TextEncoder().encode(newDocContent);
      log(`Encrypting document '${newDocTitle}'...`);

      // Encryption is a LOCAL vault op (+ a public directory lookup), so it does
      // not need a live access token — only the author's userId. Use the
      // persistent username -> sub map, which survives the short-lived Keycloak
      // token expiring, instead of gating doc creation on a fresh login.
      const authorId = getKnownUserId(currentUser.username);

      if (!authorId) throw new Error('Unknown user — log in once to register your keys.');

      // Encrypt for the author themselves. The vault resolves the recipient's key
      // from the directory and trust-checks it (own identity is always trusted).
      const authorLabel = { email: currentUser.email, name: `${currentUser.firstName} ${currentUser.lastName}` };
      const { encryptedContent, encryptedKeys } = await client.encryptWithoutKey(plainBytes.buffer as ArrayBuffer, { [authorId]: authorLabel });

      const doc: FakeDocument = {
        id: crypto.randomUUID(),
        title: newDocTitle,
        encryptedContent: abToBase64(encryptedContent),
        encryptedKeys: { [authorId]: abToBase64(encryptedKeys[authorId]) },
        createdBy: currentUser.username,
        createdAtMillis: Date.now(),
        sharedWith: [],
      };

      // Persist to the shared store; the SSE stream echoes it back into the list.
      await fetch(`${DEMO_API}?product=${PRODUCT_ID}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(doc),
      });

      setNewDocTitle('');
      setNewDocContent('');
      log(`Document encrypted (${encryptedContent.byteLength} bytes) and saved to the shared store`);
      setAttention(null);
    } catch (err) {
      log(`Encryption failed: ${(err as Error).message}`);
      const msg = attentionMessage(err);
      if (msg) setAttention(msg);
    }
  }, [currentUser, newDocTitle, newDocContent, log]);

  const handleDecryptDocument = useCallback(
    async (doc: FakeDocument) => {
      const client = clientRef.current;
      if (!client || !currentKeycloakId) return;

      try {
        log(`Decrypting '${doc.title}'...`);

        // Each authorized user has their own wrapped copy of the key. Shared
        // recipients decrypt with theirs, added at share time via shareKeys.
        const myWrappedKey = doc.encryptedKeys[currentKeycloakId];

        if (!myWrappedKey) throw new Error('No encrypted key for you on this document');

        const { data } = await client.decryptWithKey(base64ToAb(doc.encryptedContent), base64ToAb(myWrappedKey));
        const plaintext = new TextDecoder().decode(data);

        log(`Decrypted: '${plaintext}'`);
        setAttention(null);
      } catch (err) {
        log(`Decryption failed: ${(err as Error).message}`);
        const msg = attentionMessage(err);
        if (msg) setAttention(msg);
      }
    },
    [log, currentKeycloakId]
  );

  // Apply a change to a document's access list. Newly added recipients get the
  // document's symmetric key wrapped for them (shareKeys), removed recipients
  // lose their wrapped copy, and the result is persisted to the shared store.
  // The creator's own key is always preserved so they never lock themselves out.
  const handleAccessesChange = useCallback(
    async (doc: FakeDocument, newAccesses: SharedAccess[]) => {
      const client = clientRef.current;
      if (!client || !currentKeycloakId) return;

      try {
        const myWrappedKey = doc.encryptedKeys[currentKeycloakId];
        if (!myWrappedKey) throw new Error('You have no key for this document, so you cannot re-share it');

        const creatorId = getKnownUserId(doc.createdBy);
        const keptIds = new Set<string>(newAccesses.map((a) => a.userId));
        if (creatorId) keptIds.add(creatorId);

        // Keep the creator's and still-shared recipients' wrapped keys; drop the rest.
        const nextKeys: Record<string, string> = {};
        for (const [uid, wrapped] of Object.entries(doc.encryptedKeys)) {
          if (keptIds.has(uid)) nextKeys[uid] = wrapped;
        }

        // Wrap the key for newly added recipients (already TOFU-checked in the
        // share modal). Pass a labeled map: the vault resolves + trust-checks
        // each userId, and the labels feed the trust modal if one is untrusted.
        const newRecipients = newAccesses.filter((a) => a.publicKey && !nextKeys[a.userId]);

        if (newRecipients.length > 0) {
          const recipients: Record<string, RecipientLabel> = {};
          for (const a of newRecipients) recipients[a.userId] = { email: a.email, name: a.fullName };

          const { encryptedKeys } = await client.shareKeys(base64ToAb(myWrappedKey), recipients);
          for (const [uid, wrapped] of Object.entries(encryptedKeys)) nextKeys[uid] = abToBase64(wrapped);
          log(`Wrapped the document key for ${newRecipients.length} new recipient(s)`);
        }

        await fetch(`${DEMO_API}/${doc.id}?product=${PRODUCT_ID}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sharedWith: newAccesses, encryptedKeys: nextKeys }),
        });

        // Reflect the change in the open modal immediately; SSE refreshes the list.
        setShareDoc((prev) => (prev && prev.id === doc.id ? { ...prev, sharedWith: newAccesses, encryptedKeys: nextKeys } : prev));
      } catch (err) {
        log(`Sharing update failed: ${(err as Error).message}`);
      }
    },
    [currentKeycloakId, log]
  );

  const currentToken = currentUser ? getToken(currentUser.username) : null;

  return (
    <CunninghamProvider>
      <div style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 1000, margin: '0 auto', padding: 24 }}>
        <header style={{ borderBottom: '2px solid #000091', paddingBottom: 16, marginBottom: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <h1 style={{ color: '#000091', margin: 0 }}>{productName}</h1>
              <p style={{ color: '#666', margin: '4px 0 0', fontSize: 13 }}>
                Port {window.location.port} — Demo app: encryption keys and fingerprint trust/refuse decisions persist in the vault (IndexedDB).
                Documents and sharing live in a shared dev-only server store (in-memory, resets on server restart), so every demo instance — this tab,
                the other port, a private window — sees the same list live.
              </p>
            </div>
          </div>

          {/* User login/select bar */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            {DEMO_USERS.map((user) => {
              const loggedIn = isLoggedIn(user.username);
              const isActive = currentUser?.username === user.username;

              return (
                <div
                  key={user.username}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                    padding: '4px 8px',
                    borderRadius: 6,
                    fontSize: 12,
                    border: isActive ? '2px solid #000091' : '1px solid #ddd',
                    background: isActive ? '#f0f0ff' : loggedIn ? '#f0fff0' : 'white',
                  }}
                >
                  <span style={{ fontWeight: isActive ? 700 : 400 }}>
                    {user.firstName}
                    {loggedIn && <span style={{ color: '#18753c', marginLeft: 4 }}>●</span>}
                  </span>

                  {/* One click: logs in on demand (or re-logs in on expiry), then selects. */}
                  {!isActive && (
                    <button onClick={() => handleSelectUser(user)} style={{ fontSize: 11, padding: '1px 6px', cursor: 'pointer' }}>
                      Select
                    </button>
                  )}

                  {loggedIn && (
                    <button
                      onClick={() => handleLogout(user)}
                      style={{ fontSize: 11, padding: '1px 6px', cursor: 'pointer', color: '#ce0500' }}
                      title="Log out"
                    >
                      ×
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </header>

        {/* Status */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '10px 16px',
            borderRadius: 8,
            marginBottom: 20,
            background: state === 'ready' ? '#e6f5e6' : state === 'no-keys' ? '#fff3e0' : state === 'error' ? '#fce4ec' : '#f5f5f5',
          }}
        >
          <span
            style={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              background: state === 'ready' ? '#4caf50' : state === 'no-keys' ? '#ff9800' : state === 'error' ? '#f44336' : '#9e9e9e',
            }}
          />
          <span style={{ fontWeight: 600, fontSize: 14 }}>
            {state === 'not-connected' && 'Select a user to start'}
            {state === 'loading' && 'Loading...'}
            {state === 'no-keys' && 'No encryption keys — Onboarding required'}
            {state === 'ready' && `Encryption ready for ${currentUser?.firstName}`}
            {state === 'error' && 'Connection error'}
          </span>
          {state === 'no-keys' && (
            <button onClick={handleOpenOnboarding} style={{ marginLeft: 'auto', padding: '4px 12px', cursor: 'pointer' }}>
              Enable encryption
            </button>
          )}
          {state === 'ready' && (
            <button onClick={handleOpenSettings} style={{ marginLeft: 'auto', padding: '4px 12px', cursor: 'pointer' }}>
              Settings
            </button>
          )}
        </div>

        {/* Attention banner: a product surfaces vault issues here (and typically as
            a badge on its encryption menu icon) so the user knows to open the
            iframe, rather than only seeing per-document decryption failures. */}
        {attention && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              padding: '10px 16px',
              borderRadius: 8,
              marginBottom: 20,
              background: '#fff3cd',
              border: '1px solid #ffe08a',
            }}
          >
            <span style={{ fontSize: 18 }}>⚠️</span>
            <span style={{ fontSize: 14, flex: 1 }}>{attention}</span>
            <button onClick={handleOpenSettings} style={{ padding: '4px 12px', cursor: 'pointer' }}>
              Open encryption
            </button>
            <button
              onClick={() => setAttention(null)}
              style={{ padding: '4px 8px', cursor: 'pointer', background: 'transparent', border: 'none', fontSize: 16 }}
              aria-label="Dismiss"
            >
              ✕
            </button>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          {/* Left: Documents + Interface container */}
          <div>
            {/* Interface iframe container — only visible when an interface is open */}
            <div style={{ marginBottom: 16, display: interfaceOpen ? 'block' : 'none' }}>
              <h3 style={{ margin: '0 0 8px', fontSize: 14, color: '#666' }}>Encryption interface</h3>
              <div ref={setInterfaceContainer} style={{ border: '1px dashed #ddd', borderRadius: 8, minHeight: 40 }} />
            </div>

            {/* Create document — hidden while the onboarding/settings interface is
                open, so it only appears once encryption is fully set up. */}
            {state === 'ready' && !interfaceOpen && (
              <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8, marginBottom: 16 }}>
                <h3 style={{ margin: '0 0 8px' }}>Create an encrypted document</h3>
                <input
                  type="text"
                  value={newDocTitle}
                  onChange={(e) => setNewDocTitle(e.target.value)}
                  placeholder="Document title"
                  style={{ width: '100%', padding: 8, marginBottom: 8, boxSizing: 'border-box' }}
                />
                <textarea
                  value={newDocContent}
                  onChange={(e) => setNewDocContent(e.target.value)}
                  placeholder="Content to encrypt..."
                  rows={3}
                  style={{ width: '100%', padding: 8, boxSizing: 'border-box', marginBottom: 8 }}
                />
                <button
                  onClick={handleCreateDocument}
                  disabled={!newDocTitle.trim() || !newDocContent.trim()}
                  style={{ padding: '6px 12px', cursor: 'pointer' }}
                >
                  Encrypt and save
                </button>
              </section>
            )}

            {/* Document list */}
            {documents.length > 0 && (
              <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8 }}>
                <h3 style={{ margin: '0 0 8px' }}>Documents ({documents.length})</h3>
                {documents.map((doc) => (
                  <div
                    key={doc.id}
                    style={{ padding: 8, borderBottom: '1px solid #eee', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <div>
                      <strong>{doc.title}</strong>
                      <div style={{ fontSize: 11, color: '#888' }}>
                        by {doc.createdBy} — {new Date(doc.createdAtMillis).toLocaleTimeString()}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button onClick={() => setShareDoc(doc)} style={{ padding: '4px 8px', fontSize: 12, cursor: 'pointer' }}>
                        Share
                      </button>
                      <button onClick={() => handleDecryptDocument(doc)} style={{ padding: '4px 8px', fontSize: 12, cursor: 'pointer' }}>
                        Decrypt
                      </button>
                    </div>
                  </div>
                ))}
              </section>
            )}
          </div>

          {/* Right: Logs */}
          <div>
            <section style={{ padding: 16, border: '1px solid #ddd', borderRadius: 8, height: '100%', boxSizing: 'border-box' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h3 style={{ margin: 0 }}>Activity Log</h3>
                <button onClick={() => setLogs([])} style={{ padding: '2px 8px', fontSize: 12, cursor: 'pointer' }}>
                  Clear
                </button>
              </div>
              <div
                ref={logsContainerRef}
                style={{
                  fontFamily: 'monospace',
                  fontSize: 12,
                  background: '#1e1e1e',
                  color: '#d4d4d4',
                  padding: 12,
                  borderRadius: 4,
                  maxHeight: 500,
                  overflowY: 'auto',
                  minHeight: 200,
                }}
              >
                {logs.length === 0 ? (
                  <span style={{ color: '#666' }}>No activity...</span>
                ) : (
                  logs.map((line, i) => (
                    <div key={i} style={{ marginBottom: 2 }}>
                      {line}
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>
        </div>

        <footer style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid #ddd', fontSize: 12, color: '#999' }}>
          Two separate demo products run on ports 7201 (Product A) and 7202 (Product B), like Docs and Drive: each has its OWN documents, but the same
          account&apos;s encryption keys work on both via the shared vault iframe. A document created on one product stays on that product; switch the
          active user to test sharing between users within a product.
        </footer>

        {shareDoc && (
          <ShareDocumentModal
            isOpen={true}
            onClose={() => setShareDoc(null)}
            documentTitle={shareDoc.title}
            currentUserId={currentToken?.userId ?? null}
            vaultClient={clientRef.current}
            resolveUserId={getKnownUserId}
            accesses={shareDoc.sharedWith}
            onAccessesChange={(newAccesses) => handleAccessesChange(shareDoc, newAccesses)}
          />
        )}
      </div>
    </CunninghamProvider>
  );
}
