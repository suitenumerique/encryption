import { Button, Modal, ModalSize } from '@gouvfr-lasuite/ui-components';
import { useTranslation } from 'react-i18next';

import { Screen } from '@encryption/src/ui/components/layout/Screen';

/**
 * The user got back into their vault without the council (their phrase, a
 * trusted contact's, another device) while a request to it was open: the
 * server closed it, and this says so where it happened.
 */
export function CouncilClosedDialog({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { t } = useTranslation('common');

  return (
    <Modal isOpen={isOpen} onClose={onClose} closeOnClickOutside={false} size={ModalSize.SMALL} aria-label={t('council.closed_title')}>
      <Screen
        title={t('council.closed_title')}
        description={t('council.closed_body')}
        actions={<Button onClick={onClose}>{t('council.closed_ok')}</Button>}
      />
    </Modal>
  );
}
