import { CunninghamProvider } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { VaultClient } from '@encryption/src/client/vault-client';
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
import type { VaultResponse } from '@encryption/src/shared/schemas/post-message';

type EncryptionState = 'loading' | 'no-keys' | 'ready' | 'error' | 'not-connected';

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

interface FakeDocument {
  id: string;
  title: string;
  content: string;
  encryptedContent: ArrayBuffer | null;
  encryptedKey: ArrayBuffer | null;
  createdBy: string;
  createdAt: Date;
  sharedWith: SharedAccess[];
}

function sendPrivilegedRequest(iframe: HTMLIFrameElement, type: string, payload?: Record<string, unknown>): Promise<unknown> {
  const requestId = crypto.randomUUID();
  const origin = new URL(VAULT_URL).origin;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      window.removeEventListener('message', handler);
      reject(new Error('Request timed out'));
    }, 30000);

    function handler(event: MessageEvent) {
      if (event.origin !== origin) return;
      const data = event.data as VaultResponse;
      if (data?.type !== 'vault:result' || !('requestId' in data) || data.requestId !== requestId) return;

      clearTimeout(timeout);
      window.removeEventListener('message', handler);

      if (data.success) resolve(data.data);
      else reject(new Error(data.error));
    }

    window.addEventListener('message', handler);
    iframe.contentWindow!.postMessage({ type, requestId, ...(payload ? { payload } : {}) }, origin);
  });
}

export function DemoApp() {
  const clientRef = useRef<VaultClient | null>(null);
  const [state, setState] = useState<EncryptionState>('not-connected');
  const [currentUser, setCurrentUser] = useState<DemoUser | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
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

  // Force re-render when login state changes
  const [, setLoginVersion] = useState(0);
  const refreshLoginState = useCallback(() => setLoginVersion((v) => v + 1), []);

  const productName = window.location.port === '7202' ? 'Product B' : 'Product A';

  const log = useCallback((msg: string) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  }, []);

  // Pre-resolve all demo users' Keycloak subs so the Share modal can look them up
  useEffect(() => {
    resolveAllDemoUserIds();
  }, []);

  // Initialize vault client
  useEffect(() => {
    const client = new VaultClient({ vaultUrl: VAULT_URL, interfaceUrl: INTERFACE_URL, theme: 'light' });
    clientRef.current = client;

    client.on('vault:ready', () => log('Vault ready'));
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

  // Login a user via Keycloak
  const handleLogin = useCallback(
    async (user: DemoUser) => {
      log(`Logging in ${user.firstName} ${user.lastName}...`);

      try {
        const entry = await loginUser(user.username);
        log(`Authenticated ${user.firstName} (sub: ${entry.userId.slice(0, 8)}...)`);
        refreshLoginState();
      } catch (err) {
        log(`Login failed for ${user.firstName}: ${(err as Error).message}`);
      }
    },
    [log, refreshLoginState]
  );

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

  // Select a user as the active one (must be logged in first)
  const handleSelectUser = useCallback(
    async (user: DemoUser) => {
      const client = clientRef.current;
      const tokenEntry = getToken(user.username);

      if (!client || !tokenEntry) return;

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
    [log]
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

      // Get the current user's public key to encrypt for themselves
      const { publicKey } = await client.getPublicKey();
      const tokenEntry = getToken(currentUser.username);

      if (!tokenEntry) throw new Error('Not authenticated');

      const { encryptedContent, encryptedKeys } = await client.encryptWithoutKey(
        plainBytes.buffer as ArrayBuffer,
        { [tokenEntry.userId]: publicKey }
      );

      const doc: FakeDocument = {
        id: crypto.randomUUID(),
        title: newDocTitle,
        content: newDocContent,
        encryptedContent,
        encryptedKey: encryptedKeys[tokenEntry.userId],
        createdBy: currentUser.username,
        createdAt: new Date(),
        sharedWith: [],
      };

      setAllDocuments((prev) => [...prev, doc]);
      setNewDocTitle('');
      setNewDocContent('');
      log(`Document encrypted (${encryptedContent.byteLength} bytes)`);
    } catch (err) {
      log(`Encryption failed: ${(err as Error).message}`);
    }
  }, [currentUser, newDocTitle, newDocContent, log]);

  const handleDecryptDocument = useCallback(
    async (doc: FakeDocument) => {
      const client = clientRef.current;
      if (!client || !doc.encryptedContent) return;

      try {
        log(`Decrypting '${doc.title}'...`);
        if (!doc.encryptedKey) throw new Error('No encrypted key for this document');
        const { data } = await client.decryptWithKey(doc.encryptedContent, doc.encryptedKey);
        const plaintext = new TextDecoder().decode(data);
        log(`Decrypted: '${plaintext}'`);
      } catch (err) {
        log(`Decryption failed: ${(err as Error).message}`);
      }
    },
    [log]
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
                Port {window.location.port} — Demo app: encryption keys and fingerprint trust/refuse decisions persist in the vault (IndexedDB). Documents and sharing are in-memory only (local to this tab). Some UI state may not be kept across modal close/open.
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

                  {!loggedIn && (
                    <button onClick={() => handleLogin(user)} style={{ fontSize: 11, padding: '1px 6px', cursor: 'pointer' }}>
                      Login
                    </button>
                  )}

                  {loggedIn && !isActive && (
                    <button onClick={() => handleSelectUser(user)} style={{ fontSize: 11, padding: '1px 6px', cursor: 'pointer' }}>
                      Select
                    </button>
                  )}

                  {loggedIn && (
                    <button onClick={() => handleLogout(user)} style={{ fontSize: 11, padding: '1px 6px', cursor: 'pointer', color: '#ce0500' }}>
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
            {state === 'not-connected' && 'Login and select a user to start'}
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

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          {/* Left: Documents + Interface container */}
          <div>
            {/* Interface iframe container — only visible when an interface is open */}
            <div style={{ marginBottom: 16, display: interfaceOpen ? 'block' : 'none' }}>
              <h3 style={{ margin: '0 0 8px', fontSize: 14, color: '#666' }}>Encryption interface</h3>
              <div ref={setInterfaceContainer} style={{ border: '1px dashed #ddd', borderRadius: 8, minHeight: 40 }} />
            </div>

            {/* Create document */}
            {state === 'ready' && (
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
                        by {doc.createdBy} — {doc.createdAt.toLocaleTimeString()}
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
          Two instances of this demo product run on ports 7201 and 7202, proving that encryption works across different origins via the same vault
          iframe.
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
            onAccessesChange={(newAccesses) => {
              setAllDocuments((prev) => prev.map((d) => (d.id === shareDoc.id ? { ...d, sharedWith: newAccesses } : d)));
              setShareDoc((prev) => (prev ? { ...prev, sharedWith: newAccesses } : null));
            }}
          />
        )}
      </div>
    </CunninghamProvider>
  );
}
