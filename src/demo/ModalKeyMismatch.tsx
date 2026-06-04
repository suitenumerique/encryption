import { Button, Modal, ModalSize } from '@gouvfr-lasuite/cunningham-react';

import { useKeyFingerprint } from '@encryption/src/demo/useKeyFingerprint';

interface ModalKeyMismatchProps {
  onClose: () => void;
  onAcceptKey?: () => void;
  onRefuseKey?: () => void;
  knownKey?: string;
  currentKey?: string;
}

/**
 * Modal warning about a detected public key change.
 * Shows both fingerprints (previously known vs current) for manual verification.
 * Adapted from docs/src/features/docs/doc-share/components/ModalKeyMismatch.tsx
 */
export function ModalKeyMismatch({ onClose, onAcceptKey, onRefuseKey, knownKey, currentKey }: ModalKeyMismatchProps) {
  const knownFingerprint = useKeyFingerprint(knownKey);
  const currentFingerprint = useKeyFingerprint(currentKey);

  return (
    <Modal
      isOpen
      closeOnClickOutside
      onClose={onClose}
      size={ModalSize.MEDIUM}
      rightActions={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          {onRefuseKey && (
            <Button
              color="error"
              onClick={() => {
                onRefuseKey();
                onClose();
              }}
            >
              Refuse this key
            </Button>
          )}
          {onAcceptKey && (
            <Button
              color="warning"
              onClick={() => {
                onAcceptKey();
                onClose();
              }}
            >
              I trust this key
            </Button>
          )}
        </>
      }
      title={
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 18, fontWeight: 700 }}>
          <span className="material-icons" style={{ color: 'var(--c--globals--colors--warning-500, #b34000)' }}>
            warning
          </span>
          Public key change detected
        </span>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12 }}>
        <p style={{ margin: 0, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
          This user&apos;s encryption public key has changed since you last interacted with them.
        </p>
        <p style={{ margin: 0, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
          This could mean the user has regenerated their encryption keys, but it could also indicate that their account has been compromised.
        </p>
        <p style={{ margin: 0, fontWeight: 600, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
          We recommend verifying with this person directly (e.g. via video call) that they have indeed changed their encryption key before proceeding.
        </p>
        {(knownFingerprint || currentFingerprint) && (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 4,
              marginTop: 8,
              padding: 12,
              background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
              border: '1px solid var(--c--contextuals--border--surface--primary, #ddd)',
              borderRadius: 4,
            }}
          >
            {knownFingerprint && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
                  Previously known:
                </span>
                <span style={{ fontSize: 12, fontFamily: 'monospace', letterSpacing: '0.05em' }}>{knownFingerprint}</span>
              </div>
            )}
            {currentFingerprint && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>Current key:</span>
                <span style={{ fontSize: 12, fontFamily: 'monospace', letterSpacing: '0.05em' }}>{currentFingerprint}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
