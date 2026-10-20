import {
  Button,
  DropdownMenu,
  type DropdownMenuOption,
  HorizontalSeparator,
  Icon,
  InvitationUserSelectorList,
  Modal,
  ModalSize,
  QuickSearch,
  QuickSearchGroup,
  QuickSearchItemTemplate,
  Tooltip,
  UserAvatar,
} from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useState } from 'react';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import { RoleDropdown } from '@encryption/src/product-patterns/RoleDropdown';
import illustrationDocumentEncrypted from '@encryption/src/product-patterns/assets/document-encrypted.svg';
import { DocsPendingEncryptionSection, type DocsPendingRow } from '@encryption/src/product-patterns/docs/DocsPendingEncryptionSection';
import { type PatternUser, me } from '@encryption/src/product-patterns/fixtures';
import type { PatternTranslate } from '@encryption/src/product-patterns/strings';

// Docs does not use the design system's ShareModal: DocShareModal.tsx draws its
// own dialog from the same parts (Modal, QuickSearch, a row per person), which
// is where it puts what the generic modal has no slot for: a status next to a
// name, the avatar as a button, a hint under the search results. This mirrors
// that composition with the design system's exported parts.

const MIN_QUERY_LENGTH = 5;

export interface DocsMember {
  user: PatternUser;
  role: 'reader' | 'editor' | 'administrator' | 'owner';
  /** `is_pending_encryption` on the access: added before they had encryption. */
  pendingEncryption?: boolean;
}

export interface DocsSearchResult {
  user: PatternUser;
  /** False when the directory has no encryption key for them. */
  hasKeys: boolean;
}

/** Why the viewer cannot open the encrypted document (useEncryptionAccessCopy.tsx). */
export type DocsAccessError = 'needs-setup' | 'no-key' | 'pending-needs-setup' | 'pending';

export interface DocsShareDialogProps {
  encrypted: boolean;
  members?: DocsMember[];
  invitations?: { email: string; role: DocsMember['role'] }[];
  pending?: DocsPendingRow[];
  search?: { query: string; results: DocsSearchResult[] };
  selected?: PatternUser[];
  accessError?: DocsAccessError;
}

function docsRoles(t: PatternTranslate): DropdownMenuOption[] {
  return [
    { label: t('docsRoleReader'), value: 'reader' },
    { label: t('docsRoleEditor'), value: 'editor' },
    { label: t('docsRoleAdministrator'), value: 'administrator' },
    { label: t('docsRoleOwner'), value: 'owner' },
  ];
}

interface UserRowStatus {
  label: string;
  hint: string;
  icon?: string;
}

// SearchUserRow.tsx: avatar (a button opening the person's encryption identity
// on an encrypted document), name with an optional status, email below.
function DocsUserRow({
  user,
  right,
  alwaysShowRight = false,
  isInvitation = false,
  suffix,
  verifiable = false,
}: {
  user: PatternUser;
  right: ReactNode;
  alwaysShowRight?: boolean;
  isInvitation?: boolean;
  suffix?: UserRowStatus;
  verifiable?: boolean;
}) {
  const t = usePatternTranslate();
  const name = user.full_name || user.email;
  const avatar = <UserAvatar fullName={name} size="small" forceColor={isInvitation ? 'var(--c--globals--colors--gray-400)' : undefined} />;

  return (
    <QuickSearchItemTemplate
      alwaysShowRight={alwaysShowRight}
      right={right}
      left={
        <div className="pp-docs-user-row">
          {verifiable ? (
            <button
              type="button"
              className="pp-docs-user-row__avatar-button"
              aria-label={t('docsVerifyIdentityOf', { name })}
              title={t('docsVerifyIdentityOf', { name })}
              onClick={(event) => {
                event.stopPropagation();
              }}
            >
              {avatar}
            </button>
          ) : (
            avatar
          )}
          <div className="pp-docs-user-row__text">
            <div className="pp-docs-user-row__name-line">
              <span className="pp-docs-user-row__name">{name}</span>
              {suffix && (
                <Tooltip content={suffix.hint} placement="top">
                  <span className="pp-docs-status" aria-label={`${suffix.label}. ${suffix.hint}`}>
                    <Icon name={suffix.icon ?? 'gpp_bad'} size={14} />
                    <span>{suffix.label}</span>
                  </span>
                </Tooltip>
              )}
            </div>
            {user.full_name && user.full_name !== user.email && <span className="pp-docs-user-row__email">{user.email}</span>}
          </div>
        </div>
      }
    />
  );
}

function AddAction() {
  const t = usePatternTranslate();

  return (
    <span className="c__search-user-item-right pp-docs-add">
      <span>{t('docsAdd')}</span>
      <Icon name="add" />
    </span>
  );
}

// DocVisibility.tsx: hidden on an encrypted document (DocShareModalFooter.tsx),
// whose link must stay private.
function DocsVisibility() {
  const t = usePatternTranslate();
  const [isOpen, setIsOpen] = useState(false);

  return (
    <section className="pp-docs-visibility" aria-label={t('docsLinkSettings')}>
      <h2 className="pp-docs-visibility__title">{t('docsLinkSettings')}</h2>
      <div className="pp-docs-visibility__row">
        <DropdownMenu
          isOpen={isOpen}
          onOpenChange={setIsOpen}
          selectedValues={['restricted']}
          options={[
            { label: t('docsReachPrivate'), value: 'restricted' },
            { label: t('docsReachConnected'), value: 'authenticated' },
            { label: t('docsReachPublic'), value: 'public' },
          ]}
        >
          <Button
            variant="tertiary"
            size="small"
            icon={<Icon name="lock" />}
            aria-label={t('docsDocumentVisibility')}
            onClick={() => setIsOpen(!isOpen)}
          >
            {t('docsReachPrivate')}
          </Button>
        </DropdownMenu>
        <span className="pp-docs-visibility__description">{t('docsReachPrivateDescription')}</span>
      </div>
    </section>
  );
}

// EncryptionLayout.tsx `EncryptionEmptyState`, with the copy of useEncryptionAccessCopy.tsx.
export function DocsEncryptionEmptyState({ reason }: { reason: DocsAccessError }) {
  const t = usePatternTranslate();
  const isPending = reason === 'pending' || reason === 'pending-needs-setup';
  const title = isPending ? t('docsWaitingForAccess') : t('docsEncryptedDocument');
  const description = {
    pending: t('docsPendingSetUp'),
    'pending-needs-setup': t('docsPendingNeedsSetup'),
    'needs-setup': t('docsNeedsSetup'),
    'no-key': t('docsNoKeyForYou'),
  }[reason];

  return (
    <div className="pp-docs-empty-state" data-testid="docs-encryption-empty-state">
      <img src={illustrationDocumentEncrypted} alt="" width={102} height={72} />
      <p className="pp-docs-empty-state__title">{title}</p>
      <p className="pp-docs-empty-state__description">{description}</p>
    </div>
  );
}

function searchHint(t: PatternTranslate, query: string, results: DocsSearchResult[]): string {
  if (query.length < MIN_QUERY_LENGTH) {
    return t('docsHintMinLength', { minLength: MIN_QUERY_LENGTH });
  }

  if (isEmail(query)) {
    return t('docsChooseEmail');
  }

  if (results.length === 0) {
    return t('docsNoResults');
  }

  return t('docsChooseUser');
}

function isEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function DocsShareDialog({
  encrypted,
  members = [],
  invitations = [],
  pending = [],
  search,
  selected = [],
  accessError,
}: DocsShareDialogProps) {
  const t = usePatternTranslate();
  const roles = docsRoles(t);
  const [inputValue, setInputValue] = useState(search?.query ?? '');
  const query = search?.query ?? '';
  const results = search?.results ?? [];
  const showMemberSection = query === '' && selected.length === 0;
  const showFooter = selected.length === 0 && query === '';
  const emailNotFound = isEmail(query) && !results.some((result) => result.user.email.toLowerCase() === query.toLowerCase());

  return (
    <Modal
      isOpen
      closeOnClickOutside
      aria-label={t('docsShareTitle')}
      size={ModalSize.LARGE}
      onClose={() => undefined}
      hideCloseButton
      title={
        <div className="pp-docs-title">
          <h1 className="pp-docs-title__text">{t('docsShareTitle')}</h1>
          <Button variant="tertiary" color="neutral" size="small" aria-label={t('docsCloseShare')} icon={<Icon name="close" />} />
        </div>
      }
    >
      {accessError ? (
        <DocsEncryptionEmptyState reason={accessError} />
      ) : (
        <div className="pp-docs-share" data-testid="docs-share-dialog">
          {selected.length > 0 && (
            <div className="pp-docs-share__selected">
              <InvitationUserSelectorList
                users={selected}
                onRemoveUser={() => undefined}
                onShare={() => undefined}
                shareButtonLabel={t('docsInvite')}
                roles={roles}
                selectedRole="editor"
                onSelectRole={() => undefined}
              />
            </div>
          )}

          {encrypted && <DocsPendingEncryptionSection rows={pending} />}

          <QuickSearch
            label={t('docsSearchResults')}
            onFilter={setInputValue}
            inputValue={inputValue}
            showInput
            placeholder={t('docsSearchPlaceholder')}
          >
            {showMemberSection && (
              <div className="pp-docs-share__groups">
                {invitations.length > 0 && (
                  <>
                    <QuickSearchGroup
                      group={{ groupName: t('docsPendingInvitations'), elements: invitations }}
                      renderElement={(invitation) => (
                        <DocsUserRow
                          isInvitation
                          alwaysShowRight
                          user={{ id: invitation.email, full_name: invitation.email, email: invitation.email }}
                          right={<RoleDropdown roles={roles} selectedRole={invitation.role} />}
                        />
                      )}
                    />
                    <HorizontalSeparator />
                  </>
                )}
                <QuickSearchGroup
                  group={{
                    groupName: members.length === 1 ? t('docsDocumentOwner') : t('docsShareWithOther', { count: members.length }),
                    elements: members,
                  }}
                  renderElement={(member) => (
                    <DocsUserRow
                      alwaysShowRight
                      user={member.user}
                      verifiable={encrypted && member.user.id !== me.id}
                      suffix={
                        encrypted && member.pendingEncryption
                          ? { label: t('docsWaitingForEncryption'), hint: t('docsWaitingMemberHint'), icon: 'schedule' }
                          : undefined
                      }
                      right={<RoleDropdown roles={roles} selectedRole={member.role} canUpdate={member.user.id !== me.id} />}
                    />
                  )}
                />
              </div>
            )}

            {!showMemberSection && search && (
              <div className="pp-docs-share__search">
                <QuickSearchGroup
                  group={{
                    groupName: searchHint(t, query, results),
                    elements: results,
                    // Docs' own group always shows its heading, which carries the hint.
                    showWhenEmpty: true,
                    endActions: emailNotFound
                      ? [
                          {
                            content: <DocsUserRow user={{ id: query, full_name: '', email: query }} right={<AddAction />} alwaysShowRight />,
                          },
                        ]
                      : undefined,
                  }}
                  renderElement={(result) => (
                    <DocsUserRow
                      user={result.user}
                      verifiable={encrypted}
                      right={<AddAction />}
                      alwaysShowRight
                      suffix={encrypted && !result.hasKeys ? { label: t('docsNoEncryption'), hint: t('docsNoEncryptionHint') } : undefined}
                    />
                  )}
                />
                {encrypted && emailNotFound && <p className="pp-docs-share__hint">{t('docsEncryptedInviteHint')}</p>}
              </div>
            )}
          </QuickSearch>

          {showFooter && (
            <div className="pp-docs-footer">
              <HorizontalSeparator />
              {!encrypted && (
                <>
                  <DocsVisibility />
                  <HorizontalSeparator />
                </>
              )}
              <div className="pp-docs-footer__actions">
                <Button variant="secondary" icon={<Icon name="add_link" />}>
                  {t('docsCopyLink')}
                </Button>
                <Button>{t('docsOk')}</Button>
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
