/**
 * Share document modal — adapted from docs/DocShareModal.tsx
 *
 * Uses QuickSearch + QuickSearchGroup from ui-kit with custom renderElement
 * for suffix warnings.
 * Stripped of Docs-specific dependencies (Box, Text, useDocAccesses, etc.)
 *
 * Trust decisions (verifying an unknown/changed recipient key) are NOT handled
 * here: the demo simply calls shareKeys, and the SDK auto-opens the shared
 * "verify recipients" interface modal whenever a share hits UNTRUSTED_RECIPIENT.
 *
 * DEMO LIMITATIONS:
 * - Documents and accesses are in-memory only (local to the tab).
 */
import { Button, Modal, ModalSize } from '@gouvfr-lasuite/cunningham-react';
import { QuickSearch, QuickSearchData, QuickSearchGroup, QuickSearchItemTemplate } from '@gouvfr-lasuite/ui-kit';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { RegisteredUser, VaultClient } from '@encryption/src/client/vault-client';
import { uint8ToBase64 } from '@encryption/src/crypto';
import { ModalNoKey } from '@encryption/src/demo/ModalNoKey';
import { DEMO_USERS } from '@encryption/src/demo/auth';
import type { RecipientLabel } from '@encryption/src/shared/schemas/interface-context';

// ─── Types ───────────────────────────────────────────────────────

interface SharedAccess {
  userId: string;
  fullName: string;
  email: string;
  publicKey: string | null;
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
  signature_public_key: string | null;
  binding_verified: boolean;
}

// ─── VerifyButton — opens the recipient profile / verify screen ──
// Discreet affordance that opens the encryption interface at this recipient's
// profile (trust decision, fingerprint, Trust/Refuse). Only rendered for
// recipients that actually have an encryption key: there is nothing to verify
// for someone who has not enabled encryption.

function VerifyButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      title="Verify this contact's identity"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 3,
        background: 'none',
        border: 'none',
        color: 'var(--c--globals--colors--brand-400, #000091)',
        padding: '2px 4px',
        fontSize: 12,
        cursor: 'pointer',
        whiteSpace: 'nowrap',
      }}
    >
      <span className="material-icons" style={{ fontSize: 16 }}>
        verified_user
      </span>
      Verify
    </button>
  );
}

// ─── SearchUserRow — adapted from docs/SearchUserRow.tsx ─────────

function SearchUserRow({
  user,
  suffix,
  onSuffixClick,
  right,
}: {
  user: DemoUser;
  suffix?: { text: string; color?: string };
  onSuffixClick?: () => void;
  right?: React.ReactNode;
}) {
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
              <span style={{ fontSize: 12, marginTop: -2, color: 'var(--c--contextuals--content--semantic--neutral--secondary, #666)' }}>
                {user.email}
              </span>
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
  onViewProfile,
}: {
  user: DemoUser;
  suffix?: { text: string; color?: string };
  onSuffixClick?: () => void;
  onViewProfile?: (userId: string) => void;
}) {
  return (
    <SearchUserRow
      user={user}
      suffix={suffix}
      onSuffixClick={onSuffixClick}
      right={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {onViewProfile && user.encryption_public_key && <VerifyButton onClick={() => onViewProfile(user.id)} />}
          <span style={{ display: 'flex', alignItems: 'center', gap: 2, color: 'var(--c--globals--colors--brand-400, #000091)', fontSize: 13 }}>
            Add{' '}
            <span className="material-icons" style={{ fontSize: 18 }}>
              add
            </span>
          </span>
        </div>
      }
    />
  );
}

// ─── MemberRow — shared user with role dropdown + delete ─────────

function MemberRow({
  access,
  onUpdateRole,
  onDelete,
  onViewProfile,
}: {
  access: SharedAccess;
  onUpdateRole: (role: string) => void;
  onDelete: () => void;
  onViewProfile?: (userId: string) => void;
}) {
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
      right={
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {onViewProfile && access.publicKey && <VerifyButton onClick={() => onViewProfile(access.userId)} />}
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
  onViewProfile,
}: {
  searchUsers: DemoUser[];
  onSelect: (user: DemoUser) => void;
  onViewProfile?: (userId: string) => void;
}) {
  const [noKeyUser, setNoKeyUser] = useState<DemoUser | null>(null);

  const handleSelect = useCallback(
    (user: DemoUser) => {
      if (!user.encryption_public_key) {
        setNoKeyUser(user);

        return;
      }

      if (!user.binding_verified) {
        // The directory record's identity binding did not verify — the backend
        // record is incoherent (forged / tampered). Block sharing outright; the
        // row suffix explains why.
        return;
      }

      onSelect(user);
    },
    [onSelect]
  );

  const getUserSuffix = useCallback((user: DemoUser): { text: string; color?: string } | undefined => {
    if (user.encryption_public_key && !user.binding_verified) {
      return { text: 'INVALID IDENTITY SIGNATURE — DO NOT SHARE', color: 'var(--c--globals--colors--error-500, #ce0500)' };
    }

    if (!user.encryption_public_key) {
      return { text: '(encryption not enabled)' };
    }

    return undefined;
  }, []);

  const searchData: QuickSearchData<DemoUser> = useMemo(
    () => ({
      groupName: 'Search user result',
      elements: searchUsers,
    }),
    [searchUsers]
  );

  return (
    <div style={{ padding: '0 var(--c--globals--spacings--base, 16px) var(--c--globals--spacings--3xs, 4px)' }}>
      <QuickSearchGroup
        group={searchData}
        onSelect={handleSelect}
        renderElement={(user) => <InviteUserRow user={user} suffix={getUserSuffix(user)} onViewProfile={onViewProfile} />}
      />

      {noKeyUser && <ModalNoKey userName={noKeyUser.full_name || noKeyUser.email} onClose={() => setNoKeyUser(null)} />}
    </div>
  );
}

// ─── QuickSearchGroupMember — member list ────────────────────────
// Adapted from docs/DocShareMember.tsx QuickSearchGroupMember

function QuickSearchGroupMember({
  accesses,
  onUpdateRole,
  onDelete,
  onViewProfile,
}: {
  accesses: SharedAccess[];
  onUpdateRole: (userId: string, role: string) => void;
  onDelete: (userId: string) => void;
  onViewProfile?: (userId: string) => void;
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
          <MemberRow
            access={access}
            onUpdateRole={(role) => onUpdateRole(access.userId, role)}
            onDelete={() => onDelete(access.userId)}
            onViewProfile={onViewProfile}
          />
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

      // Match every whitespace-separated token against the full "name email"
      // haystack, so "bob dupont" (spanning first + last name) matches, not just
      // single-field substrings like "bob".
      const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
      const matched = DEMO_USERS.filter((u) => {
        const haystack = `${u.firstName} ${u.lastName} ${u.email}`.toLowerCase();

        return tokens.every((tok) => haystack.includes(tok));
      });

      // The demo, like any product, only ever handles subs: the SDK fetch keys
      // by sub, verifies each record's identity binding inside the vault, and
      // returns the map keyed by the same subs.
      const subByUsername: Record<string, string> = {};

      for (const user of matched) {
        const sub = resolveUserId(user.username);

        if (sub) subByUsername[user.username] = sub;
      }

      const subs = Object.values(subByUsername);
      let resolved: Record<string, RegisteredUser> = {};

      if (subs.length > 0 && vaultClient) {
        try {
          resolved = await vaultClient.fetchPublicKeys(subs);
        } catch {
          /* server unavailable */
        }
      }

      const results: DemoUser[] = matched
        .filter((u) => subByUsername[u.username] && subByUsername[u.username] !== currentUserId)
        .map((u) => {
          const sub = subByUsername[u.username];
          const record = resolved[sub];

          return {
            id: sub,
            full_name: `${u.firstName} ${u.lastName}`,
            email: u.email,
            encryption_public_key: record?.verified ? uint8ToBase64(new Uint8Array(record.encryptionPublicKey)) : null,
            signature_public_key: record ? uint8ToBase64(new Uint8Array(record.signaturePublicKey)) : null,
            // An unverified record is the "backend tampered" signal that blocks
            // sharing (the vault already refused to expose its encryption key).
            binding_verified: record?.verified ?? false,
          };
        });

      setSearchUsers(results);
      setLoading(false);
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

  // Recipient profile overlay: clicking "View / verify" on any recipient row
  // opens the encryption interface at that person's profile screen inside a
  // demo-owned container (the interface draws its own trust/fingerprint UI).
  const [profileUserId, setProfileUserId] = useState<string | null>(null);
  const [profileContainer, setProfileContainer] = useState<HTMLDivElement | null>(null);

  // Mount (or re-target) the profile iframe once both the target userId and the
  // container element exist. Re-runs when either changes, so switching between
  // recipients re-points the same overlay.
  useEffect(() => {
    if (!profileUserId || !profileContainer || !vaultClient) return;

    // The label travels with the rows we already display (search results,
    // pending selection, existing accesses).
    const fromRows = [...searchUsers, ...selectedUsers].find((u) => u.id === profileUserId);
    const fromAccesses = accesses.find((a) => a.userId === profileUserId);
    const label: RecipientLabel | undefined = fromRows
      ? { email: fromRows.email, name: fromRows.full_name }
      : fromAccesses
        ? { email: fromAccesses.email, name: fromAccesses.fullName }
        : undefined;

    if (!label) return;

    vaultClient.openRecipientProfile(profileContainer, profileUserId, label);
  }, [profileUserId, profileContainer, vaultClient, searchUsers, selectedUsers, accesses]);

  const openProfile = useCallback(
    (userId: string) => {
      if (!vaultClient) return;

      setProfileUserId(userId);
    },
    [vaultClient]
  );

  const closeProfile = useCallback(() => {
    vaultClient?.closeInterface();
    setProfileUserId(null);
  }, [vaultClient]);

  // Only expose the affordance when there is a client to open the profile with.
  const onViewProfile = vaultClient ? openProfile : undefined;

  return (
    <>
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
                    {onViewProfile && u.encryption_public_key && (
                      <button
                        onClick={() => onViewProfile(u.id)}
                        title="Verify this contact's identity"
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: 'pointer',
                          padding: 0,
                          lineHeight: 1,
                          color: 'var(--c--globals--colors--brand-400, #000091)',
                          display: 'inline-flex',
                        }}
                      >
                        <span className="material-icons" style={{ fontSize: 16 }}>
                          verified_user
                        </span>
                      </button>
                    )}
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
                onViewProfile={onViewProfile}
              />
            )}

            {/* Search results — shown when searching (like Docs' QuickSearchInviteInputSection) */}
            {!showMemberSection && <QuickSearchInviteInputSection searchUsers={searchUsers} onSelect={onSelect} onViewProfile={onViewProfile} />}
          </QuickSearch>
        </div>
      </Modal>

      {/* Recipient profile overlay — hosts the encryption interface iframe. Sits
          above the share modal; click the backdrop or Close to dismiss. */}
      {profileUserId && (
        <div
          onClick={closeProfile}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 10000,
            background: 'rgba(0, 0, 0, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: 'white', borderRadius: 8, width: 'min(560px, 92vw)', maxHeight: '90vh', overflow: 'auto', padding: 12 }}
          >
            {/* No title here: the interface iframe renders its own "Encryption
                Identity" heading, so a second title would be redundant. */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 4 }}>
              <button
                onClick={closeProfile}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 28, lineHeight: 1, padding: '0 4px', color: '#666' }}
              >
                ×
              </button>
            </div>
            <div ref={setProfileContainer} style={{ minHeight: 200 }} />
          </div>
        </div>
      )}
    </>
  );
}
