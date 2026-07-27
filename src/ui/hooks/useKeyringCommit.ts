import { useCallback } from 'react';

import type { MnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_SIGN_REQUEST } from '@encryption/src/shared/constants';
import type { EmergencyRearmEntry, VaultKeyringUpdateBody } from '@encryption/src/shared/schemas/emergency-access';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import { deleteEmergencyAccess, fetchTrustedContacts } from '@encryption/src/ui/api/emergency-client';
import { updateVaultKeyring } from '@encryption/src/ui/api/vault-client';
import { withFreshToken } from '@encryption/src/ui/auth/session-expired';
import { UntrustedRearmError, grantedRearmRows } from '@encryption/src/ui/components/emergency-access-logic';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

/**
 * Commit a re-wrapped keyring (recovery-phrase change) to the server, with the
 * emergency burn + re-arm the server enforces: while a recovery is granted the
 * revealed emergency phrase must not survive the rotation, so a fresh escrow is
 * built for every granted relationship and carried on the same PUT. Shared by
 * the settings change-phrase flow and the forced rotation after an emergency
 * unlock, so both go through the exact same rewrite.
 */
export function useKeyringCommit(getToken: () => Promise<string | null>) {
  const { request, buildEmergencyRearms } = useEncryptionContext();

  const commitKeyring = useCallback(
    async (keyring: VaultKeyringWire, lang: MnemonicLanguage): Promise<void> => {
      const { contacts } = await withFreshToken(getToken, (token) => fetchTrustedContacts(token));
      const rows = grantedRearmRows(contacts, Date.now());

      // Build per relationship (not batched) so ONE untrusted contact does not
      // mask which rows are blocking: the failures are collected and reported
      // together for a single revoke-and-retry decision.
      const rearms: EmergencyRearmEntry[] = [];
      const untrusted: Array<{ id: string; email: string }> = [];

      for (const row of rows) {
        try {
          const { rearms: built } = await buildEmergencyRearms(
            [{ emergencyAccessId: row.emergencyAccessId, granteeUserId: row.granteeUserId, waitTimeDays: row.waitTimeDays }],
            lang
          );
          rearms.push(...built);
        } catch (err) {
          if (isVaultError(err) && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
            untrusted.push({ id: row.emergencyAccessId, email: row.granteeEmail });
          } else {
            throw err;
          }
        }
      }

      if (untrusted.length > 0) throw new UntrustedRearmError(untrusted);

      const body: VaultKeyringUpdateBody = rearms.length > 0 ? { ...keyring, emergency_rearms: rearms } : keyring;

      // Covered route: sign the EXACT body we will send (same serialization the
      // request helper uses), so the proof's body digest matches, then attach it.
      const json = JSON.stringify(body);
      const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'PUT', path: '/api/vault/keyring', body: json })) as {
        signature: string;
      };

      await withFreshToken(getToken, (token) => updateVaultKeyring(token, body, signature));
    },
    [getToken, request, buildEmergencyRearms]
  );

  /** Revoke the given relationships (used on the blocking contacts before a retry). */
  const revokeContacts = useCallback(
    async (ids: string[]): Promise<void> => {
      await withFreshToken(getToken, async (token) => {
        for (const id of ids) {
          await deleteEmergencyAccess(token, id);
        }
      });
    },
    [getToken]
  );

  return { commitKeyring, revokeContacts };
}
