import { Button, Modal, ModalSize } from '@gouvfr-lasuite/cunningham-react';

interface ModalNoKeyProps {
  userName: string;
  onClose: () => void;
}

/**
 * Modal shown when trying to share an encrypted document with a user
 * who hasn't enabled encryption yet.
 */
export function ModalNoKey({ userName, onClose }: ModalNoKeyProps) {
  return (
    <Modal
      isOpen
      closeOnClickOutside
      onClose={onClose}
      size={ModalSize.MEDIUM}
      rightActions={<Button onClick={onClose}>Understood</Button>}
      title={
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 18, fontWeight: 700 }}>
          <span className="material-icons" style={{ color: 'var(--c--globals--colors--warning-500)' }}>
            lock
          </span>
          Encryption not enabled
        </span>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12 }}>
        <p style={{ margin: 0, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
          <strong>{userName}</strong> has not enabled encryption yet. They must activate encryption on their account before you can share encrypted
          documents with them.
        </p>
        <p style={{ margin: 0, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
          Please ask them to enable encryption first, then try sharing again.
        </p>
      </div>
    </Modal>
  );
}
