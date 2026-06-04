/**
 * Share document modal — adapted from docs/DocShareModal.tsx
 *
 * Uses QuickSearch + QuickSearchGroup from ui-kit with custom renderElement
 * for fingerprint badges, suffix warnings, and key mismatch modals.
 * Stripped of Docs-specific dependencies (Box, Text, useDocAccesses, etc.)
 *
 * DEMO LIMITATIONS:
 * - Documents and accesses are in-memory only (local to the tab).
 * - Fingerprint trust/refuse decisions ARE persisted in the vault's IndexedDB
 *   (via checkFingerprints/acceptFingerprint/refuseFingerprint), so they
 *   survive modal close/reopen and page reload.
 * - Key mismatch state (unknown keys not yet decided) is ephemeral — it's
 *   recomputed on each search from the vault registry.
 */
import { Button, Modal, ModalSize } from '@gouvfr-lasuite/cunningham-react';
import { Badge, QuickSearch, QuickSearchData, QuickSearchGroup, QuickSearchItemTemplate } from '@gouvfr-lasuite/ui-kit';
import { useCallback, useMemo, useRef, useState } from 'react';

import type { VaultClient } from '@encryption/src/client/vault-client';
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { verifyKeyRegistration } from '@encryption/src/crypto/key-registration';
import { ModalKeyMismatch } from '@encryption/src/demo/ModalKeyMismatch';
import { ModalNoKey } from '@encryption/src/demo/ModalNoKey';
import { DEMO_USERS } from '@encryption/src/demo/auth';
import { useKeyFingerprint } from '@encryption/src/demo/useKeyFingerprint';
import { fetchPublicKeys, type PublicKeyEntry } from '@encryption/src/ui/api/server-client';

// ─── Types ───────────────────────────────────────────────────────

interface SharedAccess {
  userId: string;
  fullName: string;
  email: string;
  publicKey: string | null;
  /** Identity (signature) public key — what the fingerprint is computed over. */
  signaturePublicKey: string | null;
  role: string;
}

interface ShareDocumentModalProps {
  isOpen: boolean;
  onClose: () => void;
  documentTitle: string;
  currentUserId: string | null;
  vaultClient: VaultClient | null;
  resolveUserId: (username: string) => string | null;
  accesses: SharedAccess[];
  onAccessesChange: (accesses: SharedAccess[]) => void;
}

interface DemoUser {
  id: string;
  full_name: string;
  email: string;
  encryption_public_key: string | null;
  /** Identity (signature) public key — what the fingerprint is computed over. */
  signature_public_key: string | null;
  /**
   * Whether the directory record's identity binding verified. `false` means
   * the backend record is incoherent (forged / tampered) — block sharing.
   */
  binding_verified: boolean;
}

interface KeyMismatch {
  userId: string;
  knownKey: string;
  currentKey: string;
}

// ─── SearchUserRow — adapted from docs/SearchUserRow.tsx ─────────

function SearchUserRow({
  user,
  suffix,
  onSuffixClick,
  fingerprintKey,
  right,
}: {
  user: DemoUser;
  suffix?: { text: string; color?: string };
  onSuffixClick?: () => void;
  fingerprintKey?: string | null;
  right?: React.ReactNode;
}) {
  const fingerprint = useKeyFingerprint(fingerprintKey);

  return (
    <QuickSearchItemTemplate
      alwaysShowRight={!!right}
      right={right}
      left={
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--c--globals--spacings--xs, 8px)' }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              flexShrink: 0,
              background: user.encryption_public_key ? 'var(--c--globals--colors--brand-400, #000091)' : 'var(--c--globals--colors--gray-400, #999)',
              color: 'white',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 12,
              fontWeight: 700,
            }}
          >
            {(user.full_name || user.email)
              .split(' ')
              .map((n) => n[0])
              .join('')
              .slice(0, 2)
              .toUpperCase()}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--c--globals--spacings--3xs, 4px)' }}>
              <span style={{ fontSize: 14, fontWeight: 500 }}>{user.full_name || user.email}</span>
              {suffix && (
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    color: suffix.color ?? 'var(--c--globals--colors--warning-600, #b34000)',
                    ...(onSuffixClick ? { cursor: 'pointer', textDecoration: 'underline' } : {}),
                  }}
                  onClick={
                    onSuffixClick
                      ? (e) => {
                          e.stopPropagation();
                          onSuffixClick();
                        }
                      : undefined
                  }
                  role={onSuffixClick ? 'button' : undefined}
                  tabIndex={onSuffixClick ? 0 : undefined}
                >
                  {suffix.text}
                </span>
              )}
            </div>
            {user.full_name && (
              <span style={{ fontSize: 12, marginTop: -2, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>{user.email}</span>
            )}
            {fingerprint && (
              <Badge style={{ width: 'fit-content', gap: '0.3rem', margin: '5px 0' }}>
                <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>Fingerprint </span>
                <span style={{ fontSize: 10, fontFamily: 'monospace', letterSpacing: '0.05em' }}>{fingerprint}</span>
              </Badge>
            )}
          </div>
        </div>
      }
    />
  );
}

// ─── DocShareModalInviteUserRow — user row with "Add" action ────

function InviteUserRow({
  user,
  suffix,
  onSuffixClick,
  fingerprintKey,
}: {
  user: DemoUser;
  suffix?: { text: string; color?: string };
  onSuffixClick?: () => void;
  fingerprintKey?: string | null;
}) {
  return (
    <SearchUserRow
      user={user}
      suffix={suffix}
      onSuffixClick={onSuffixClick}
      fingerprintKey={fingerprintKey ?? user.signature_public_key}
      right={
        <span style={{ display: 'flex', alignItems: 'center', gap: 2, color: 'var(--c--globals--colors--brand-400, #000091)', fontSize: 13 }}>
          Add{' '}
          <span className="material-icons" style={{ fontSize: 18 }}>
            add
          </span>
        </span>
      }
    />
  );
}

// ─── MemberRow — shared user with role dropdown + delete ─────────

function MemberRow({ access, onUpdateRole, onDelete }: { access: SharedAccess; onUpdateRole: (role: string) => void; onDelete: () => void }) {
  const user: DemoUser = {
    id: access.userId,
    full_name: access.fullName,
    email: access.email,
    encryption_public_key: access.publicKey,
    signature_public_key: access.signaturePublicKey,
    binding_verified: true,
  };

  return (
    <SearchUserRow
      user={user}
      fingerprintKey={access.signaturePublicKey}
      right={
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <select
            value={access.role}
            onChange={(e) => onUpdateRole(e.target.value)}
            style={{
              padding: '4px 8px',
              borderRadius: 4,
              border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
              fontSize: 12,
            }}
          >
            <option value="editor">Editor</option>
            <option value="viewer">Viewer</option>
          </select>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onDelete();
            }}
            title="Remove"
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--c--globals--colors--error-500, #ce0500)',
              fontSize: 18,
              padding: 0,
              lineHeight: 1,
            }}
          >
            <span className="material-icons" style={{ fontSize: 18 }}>
              delete
            </span>
          </button>
        </div>
      }
    />
  );
}

// ─── QuickSearchInviteInputSection — search results with modals ──
// Adapted from docs/DocShareModal.tsx QuickSearchInviteInputSection

function QuickSearchInviteInputSection({
  searchUsers,
  onSelect,
  keyMismatchUserIds,
  refusedUserIds,
  keyMismatches,
  acceptNewKey,
  refuseKey,
  clearRefused,
}: {
  searchUsers: DemoUser[];
  onSelect: (user: DemoUser) => void;
  keyMismatchUserIds: Set<string>;
  refusedUserIds: Set<string>;
  keyMismatches: KeyMismatch[];
  acceptNewKey: (userId: string) => Promise<void>;
  refuseKey: (userId: string) => Promise<void>;
  clearRefused: (userId: string) => void;
}) {
  const [showNoKeyModal, setShowNoKeyModal] = useState(false);
  const [mismatchUser, setMismatchUser] = useState<DemoUser | null>(null);

  const handleSelect = useCallback(
    (user: DemoUser) => {
      if (!user.encryption_public_key) {
        setShowNoKeyModal(true);

        return;
      }

      if (!user.binding_verified) {
        // The directory record's identity binding did not verify — the backend
        // record is incoherent (forged / tampered). Block sharing outright; the
        // row suffix explains why.
        return;
      }

      if (refusedUserIds.has(user.id)) {
        return; // Blocked — refused key
      }

      if (keyMismatchUserIds.has(user.id)) {
        setMismatchUser(user);

        return;
      }

      onSelect(user);
    },
    [keyMismatchUserIds, refusedUserIds, onSelect]
  );

  const getUserSuffix = useCallback(
    (user: DemoUser): { text: string; color?: string } | undefined => {
      if (user.encryption_public_key && !user.binding_verified) {
        return { text: 'INVALID IDENTITY SIGNATURE — DO NOT SHARE', color: 'var(--c--globals--colors--error-500, #ce0500)' };
      }

      if (refusedUserIds.has(user.id)) {
        return { text: 'KEY REFUSED — DO NOT SHARE', color: 'var(--c--globals--colors--error-500, #ce0500)' };
      }

      if (keyMismatchUserIds.has(user.id)) {
        return { text: 'DIFFERENT PUBLIC KEY, PLEASE VERIFY' };
      }

      if (!user.encryption_public_key) {
        return { text: '(encryption not enabled)' };
      }

      return undefined;
    },
    [keyMismatchUserIds, refusedUserIds]
  );

  const searchData: QuickSearchData<DemoUser> = useMemo(
    () => ({
      groupName: 'Search user result',
      elements: searchUsers,
    }),
    [searchUsers]
  );

  const activeMismatch = mismatchUser ? keyMismatches.find((m) => m.userId === mismatchUser.id) : null;
  const isRefusedUser = mismatchUser ? refusedUserIds.has(mismatchUser.id) : false;

  return (
    <div style={{ padding: '0 var(--c--globals--spacings--base, 16px) var(--c--globals--spacings--3xs, 4px)' }}>
      <QuickSearchGroup
        group={searchData}
        onSelect={handleSelect}
        renderElement={(user) => (
          <InviteUserRow
            user={user}
            suffix={getUserSuffix(user)}
            onSuffixClick={keyMismatchUserIds.has(user.id) || refusedUserIds.has(user.id) ? () => setMismatchUser(user) : undefined}
            fingerprintKey={user.signature_public_key}
          />
        )}
      />

      {showNoKeyModal && <ModalNoKey userName="" onClose={() => setShowNoKeyModal(false)} />}

      {mismatchUser && (activeMismatch || isRefusedUser) && (
        <ModalKeyMismatch
          onClose={() => setMismatchUser(null)}
          onAcceptKey={() => {
            if (isRefusedUser) {
              clearRefused(mismatchUser.id);
            }
            void acceptNewKey(mismatchUser.id).then(() => {
              onSelect(mismatchUser);
            });
          }}
          onRefuseKey={
            !isRefusedUser
              ? () => {
                  void refuseKey(mismatchUser.id);
                }
              : undefined
          }
          knownKey={activeMismatch?.knownKey}
          currentKey={activeMismatch?.currentKey ?? mismatchUser.encryption_public_key ?? undefined}
        />
      )}
    </div>
  );
}

// ─── QuickSearchGroupMember — member list ────────────────────────
// Adapted from docs/DocShareMember.tsx QuickSearchGroupMember

function QuickSearchGroupMember({
  accesses,
  onUpdateRole,
  onDelete,
}: {
  accesses: SharedAccess[];
  onUpdateRole: (userId: string, role: string) => void;
  onDelete: (userId: string) => void;
}) {
  const membersData: QuickSearchData<SharedAccess> = useMemo(
    () => ({
      groupName: accesses.length === 1 ? 'Document owner' : `Shared with ${accesses.length} users`,
      elements: accesses,
    }),
    [accesses]
  );

  if (accesses.length === 0) return null;

  return (
    <div style={{ padding: '0 var(--c--globals--spacings--base, 16px) var(--c--globals--spacings--3xs, 4px)' }}>
      <QuickSearchGroup
        group={membersData}
        renderElement={(access) => (
          <MemberRow access={access} onUpdateRole={(role) => onUpdateRole(access.userId, role)} onDelete={() => onDelete(access.userId)} />
        )}
      />
    </div>
  );
}

// ─── Main ShareDocumentModal ─────────────────────────────────────

export function ShareDocumentModal({
  isOpen,
  onClose,
  documentTitle,
  currentUserId,
  vaultClient,
  resolveUserId,
  accesses,
  onAccessesChange,
}: ShareDocumentModalProps) {
  // Search state
  const [inputValue, setInputValue] = useState('');
  const [searchUsers, setSearchUsers] = useState<DemoUser[]>([]);
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Selection state (like Docs' selectedUsers)
  const [selectedUsers, setSelectedUsers] = useState<DemoUser[]>([]);
  const [selectedRole, setSelectedRole] = useState('editor');

  // Members state managed by parent (persists across modal open/close)

  // Key mismatch + refused tracking
  const [keyMismatches, setKeyMismatches] = useState<KeyMismatch[]>([]);
  const keyMismatchUserIds = useMemo(() => new Set(keyMismatches.map((m) => m.userId)), [keyMismatches]);
  const [refusedUserIds, setRefusedUserIds] = useState<Set<string>>(new Set());

  const showMemberSection = inputValue === '' && selectedUsers.length === 0;

  // Search handler with debounce (like Docs' onFilter + useUsers)
  const doSearch = useCallback(
    async (query: string) => {
      if (!query.trim()) {
        setSearchUsers([]);
        setLoading(false);

        return;
      }

      setLoading(true);

      const q = query.toLowerCase();
      const matched = DEMO_USERS.filter(
        (u) => u.firstName.toLowerCase().includes(q) || u.lastName.toLowerCase().includes(q) || u.email.toLowerCase().includes(q)
      );

      const userIdMap: Record<string, string> = {};

      for (const user of matched) {
        const realId = resolveUserId(user.username);

        if (realId) userIdMap[user.username] = realId;
      }

      const realIds = Object.values(userIdMap);
      const entriesById: Record<string, PublicKeyEntry> = {};

      if (realIds.length > 0) {
        try {
          const keys = await fetchPublicKeys(realIds);

          for (const key of keys) entriesById[key.user_id] = key;
        } catch {
          /* server unavailable */
        }
      }

      const results: DemoUser[] = await Promise.all(
        matched
          .filter((u) => userIdMap[u.username] && userIdMap[u.username] !== currentUserId)
          .map(async (u) => {
            const realId = userIdMap[u.username];
            const entry = entriesById[realId];

            // Verify the directory record's identity binding before trusting
            // any of its keys. An incoherent record is the "backend tampered"
            // signal that blocks sharing.
            let bindingVerified = false;

            if (entry) {
              try {
                bindingVerified = await verifyKeyRegistration({
                  userId: entry.user_id,
                  version: entry.version,
                  createdAtMillis: entry.created_at_millis,
                  encryptionPublicKeyB64: entry.encryption_public_key,
                  signaturePublicKeyB64: entry.signature_public_key,
                  keyBindingSignatureB64: entry.key_binding_signature,
                });
              } catch {
                bindingVerified = false;
              }
            }

            return {
              id: realId,
              full_name: `${u.firstName} ${u.lastName}`,
              email: u.email,
              encryption_public_key: entry?.encryption_public_key ?? null,
              signature_public_key: entry?.signature_public_key ?? null,
              binding_verified: bindingVerified,
            };
          })
      );

      setSearchUsers(results);
      setLoading(false);

      // Check fingerprints against vault registry (TOFU). The fingerprint is of
      // the IDENTITY (signature) key, and only records whose binding verified
      // are eligible — a tampered record never reaches the trust check.
      if (vaultClient && currentUserId) {
        const fps: Record<string, string> = {};

        for (const u of results) {
          if (u.signature_public_key && u.binding_verified) {
            try {
              fps[u.id] = await computeKeyFingerprint(u.signature_public_key);
            } catch {
              /* skip */
            }
          }
        }

        if (Object.keys(fps).length > 0) {
          try {
            const { results: checks } = await vaultClient.checkFingerprints(fps, currentUserId);
            const mm: KeyMismatch[] = [];
            const refused = new Set<string>();

            for (const c of checks) {
              if (c.status === 'refused') {
                refused.add(c.userId);
              } else if (c.status === 'unknown' && c.knownFingerprint) {
                const u = results.find((x) => x.id === c.userId);

                if (u?.signature_public_key) mm.push({ userId: c.userId, knownKey: c.knownFingerprint, currentKey: u.signature_public_key });
              }
            }

            setKeyMismatches(mm);
            setRefusedUserIds(refused);
          } catch {
            /* vault unavailable */
          }
        }
      }
    },
    [currentUserId, resolveUserId, vaultClient]
  );

  const onFilter = useCallback(
    (str: string) => {
      setInputValue(str);

      if (debounceRef.current) clearTimeout(debounceRef.current);

      debounceRef.current = setTimeout(() => doSearch(str), 300);
    },
    [doSearch]
  );

  // Select a user from search results (like Docs' onSelect)
  const onSelect = useCallback((user: DemoUser) => {
    setSelectedUsers((prev) => [...prev, user]);
    setInputValue('');
    setSearchUsers([]);
  }, []);

  // Accept a mismatched key
  const acceptNewKey = useCallback(
    async (userId: string) => {
      if (!vaultClient) return;

      const mm = keyMismatches.find((m) => m.userId === userId);

      if (!mm) return;

      try {
        const fp = await computeKeyFingerprint(mm.currentKey);

        await vaultClient.acceptFingerprint(userId, fp);
        setKeyMismatches((prev) => prev.filter((m) => m.userId !== userId));
      } catch {
        /* vault error */
      }
    },
    [vaultClient, keyMismatches]
  );

  // Refuse a key — marks it as dangerous in the vault registry
  const refuseKey = useCallback(
    async (userId: string) => {
      if (!vaultClient) return;

      const mm = keyMismatches.find((m) => m.userId === userId);

      if (!mm) return;

      try {
        const fp = await computeKeyFingerprint(mm.currentKey);

        await vaultClient.refuseFingerprint(userId, fp);
        setKeyMismatches((prev) => prev.filter((m) => m.userId !== userId));
        setRefusedUserIds((prev) => new Set([...prev, userId]));
      } catch {
        /* vault error */
      }
    },
    [vaultClient, keyMismatches]
  );

  return (
    <Modal
      isOpen={isOpen}
      closeOnClickOutside
      onClose={onClose}
      size={ModalSize.LARGE}
      title={<span style={{ fontSize: 16, fontWeight: 600 }}>Share &ldquo;{documentTitle}&rdquo;</span>}
    >
      <div style={{ paddingBottom: 'var(--c--globals--spacings--base, 16px)' }}>
        {/* Selected users bar — like Docs' DocShareAddMemberList */}
        {selectedUsers.length > 0 && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px var(--c--globals--spacings--base, 16px)',
              borderBottom: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
            }}
          >
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, flex: 1 }}>
              {selectedUsers.map((u) => (
                <span
                  key={u.id}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    padding: '4px 10px',
                    borderRadius: 16,
                    background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                    fontSize: 13,
                  }}
                >
                  {u.full_name}
                  <button
                    onClick={() => setSelectedUsers((prev) => prev.filter((x) => x.id !== u.id))}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 16, padding: 0, lineHeight: 1, color: '#666' }}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                fontSize: 13,
              }}
            >
              <option value="editor">Editor</option>
              <option value="viewer">Viewer</option>
            </select>
            <Button
              size="small"
              onClick={() => {
                onAccessesChange([
                  ...accesses,
                  ...selectedUsers.map((u) => ({
                    userId: u.id,
                    fullName: u.full_name,
                    email: u.email,
                    publicKey: u.encryption_public_key,
                    signaturePublicKey: u.signature_public_key,
                    role: selectedRole,
                  })),
                ]);
                setSelectedUsers([]);
              }}
            >
              Share
            </Button>
          </div>
        )}

        {/* QuickSearch — exactly like Docs */}
        <QuickSearch
          label="Search results"
          onFilter={onFilter}
          inputValue={inputValue}
          showInput
          loading={loading}
          placeholder="Search users by name or email..."
        >
          {/* Members list — shown when NOT searching (like Docs' showMemberSection) */}
          {showMemberSection && (
            <QuickSearchGroupMember
              accesses={accesses}
              onUpdateRole={(userId, role) => onAccessesChange(accesses.map((a) => (a.userId === userId ? { ...a, role } : a)))}
              onDelete={(userId) => onAccessesChange(accesses.filter((a) => a.userId !== userId))}
            />
          )}

          {/* Search results — shown when searching (like Docs' QuickSearchInviteInputSection) */}
          {!showMemberSection && (
            <QuickSearchInviteInputSection
              searchUsers={searchUsers}
              onSelect={onSelect}
              keyMismatchUserIds={keyMismatchUserIds}
              refusedUserIds={refusedUserIds}
              keyMismatches={keyMismatches}
              acceptNewKey={acceptNewKey}
              refuseKey={refuseKey}
              clearRefused={(userId) =>
                setRefusedUserIds((prev) => {
                  const next = new Set(prev);
                  next.delete(userId);
                  return next;
                })
              }
            />
          )}
        </QuickSearch>
      </div>
    </Modal>
  );
}
