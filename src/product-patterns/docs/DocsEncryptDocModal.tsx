import { Alert, Button, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import illustrationDocumentShieldCheck from '@encryption/src/product-patterns/assets/document-shield-check.png';

export interface DocsEncryptDocModalProps {
  /** The viewer has their own encryption keys (`encryptionSettings`). */
  hasKeys: boolean;
  /** The link reach; encrypting requires `restricted` (private). */
  linkReach: 'restricted' | 'authenticated' | 'public';
  analyzingUploads?: number;
  /** Members without a key plus pending email invitations. */
  pendingCount?: number;
}

// ModalEncryptDoc.tsx, opened by "Encrypt document" in the document menu
// (DocToolBox.tsx). It is where encryption meets sharing: the link must be
// private first, and members without encryption are announced as pending.
export function DocsEncryptDocModal({ hasKeys, linkReach, analyzingUploads = 0, pendingCount = 0 }: DocsEncryptDocModalProps) {
  const t = usePatternTranslate();
  const blockers: string[] = [];

  if (!hasKeys) {
    blockers.push(t('docsBlockerNoKeys'));
  }

  if (analyzingUploads > 0) {
    blockers.push(t('docsBlockerAntivirus'));
  }

  if (linkReach !== 'restricted') {
    blockers.push(t('docsBlockerNotPrivate', { reach: linkReach === 'public' ? t('docsReachLowerPublic') : t('docsReachLowerConnected') }));
  }

  const canEncrypt = blockers.length === 0;

  return (
    <Modal isOpen closeOnClickOutside onClose={() => undefined} size={ModalSize.SMALL} aria-label={t('docsEncryptDocument')}>
      <div className="pp-docs-encrypt" data-testid="docs-encrypt-modal">
        <img className="pp-docs-encrypt__illustration" src={illustrationDocumentShieldCheck} alt="" width={142} height={100} />
        <div className="pp-docs-encrypt__heading">
          <h2 className="pp-docs-encrypt__title">{t('docsEncryptDocument')}</h2>
          <p className="pp-docs-encrypt__description">{t('docsEncryptDescription')}</p>
        </div>
        {blockers.length > 0 && (
          <Alert type={VariantType.ERROR}>
            {blockers.length === 1 ? (
              blockers[0]
            ) : (
              <ul className="pp-docs-encrypt__blockers">
                {blockers.map((blocker) => (
                  <li key={blocker}>{blocker}</li>
                ))}
              </ul>
            )}
          </Alert>
        )}
        {canEncrypt && pendingCount > 0 && (
          <Alert type={VariantType.WARNING}>
            {pendingCount === 1
              ? t('docsPendingCollaboratorsOne', { count: pendingCount })
              : t('docsPendingCollaboratorsOther', { count: pendingCount })}
          </Alert>
        )}
        <div className="pp-docs-encrypt__actions">
          <Button fullWidth disabled={!canEncrypt}>
            {t('docsEncrypt')}
          </Button>
          <Button fullWidth variant="bordered" color="neutral">
            {t('docsCancel')}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
