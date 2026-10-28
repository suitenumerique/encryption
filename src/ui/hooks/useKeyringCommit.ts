import { useCallback } from 'react';

import type { MnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_FETCH_PUBLIC_KEYS, MSG_VAULT_GET_KNOWN_FINGERPRINTS, MSG_VAULT_SIGN_REQUEST } from '@encryption/src/shared/constants';
import { API_ERROR_COUNCIL_REARM_REQUIRED } from '@encryption/src/shared/error-codes';
import type { EmergencyRearmEntry, VaultKeyringUpdateBody } from '@encryption/src/shared/schemas/emergency-access';
import type { CouncilEscrowBody } from '@encryption/src/shared/schemas/recovery-council';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import { ApiError } from '@encryption/src/ui/api/client';
import { fetchCouncilForMe } from '@encryption/src/ui/api/council-client';
import { deleteEmergencyAccess, fetchTrustedContacts } from '@encryption/src/ui/api/emergency-client';
import { updateVaultKeyring } from '@encryption/src/ui/api/vault-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { type BlockedContact, UntrustedRearmError, grantedRearmRows } from '@encryption/src/ui/components/emergency-access-logic';
import type { VaultRegisteredUser } from '@encryption/src/ui/components/verify-recipients-logic';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

/**
 * Commit a re-wrapped keyring (recovery-phrase change) to the server, with the
 * emergency burn + re-arm the server enforces: while a recovery is granted the
 * revealed emergency phrase must not survive the rotation, so a fresh escrow is
 * built for every granted relationship and carried on the same PUT. Shared by
 * the settings change-phrase flow and the forced rotation after an emergency
 * unlock, so both go through the exact same rewrite.
 */
export function useKeyringCommit(getIdToken: () => Promise<string | null>) {
  const { request, buildEmergencyRearms } = useEncryptionContext();
  const councilVault = useCouncilVault();

  const commitKeyring = useCallback(
    async (
      keyring: VaultKeyringWire,
      lang: MnemonicLanguage,
      council?: { councilRearm?: CouncilEscrowBody; councilDrop?: boolean }
    ): Promise<void> => {
      const { contacts } = await withFreshIdToken(getIdToken, (idToken) => fetchTrustedContacts(idToken));
      const rows = grantedRearmRows(contacts, Date.now());

      // Build per relationship (not batched) so ONE untrusted contact does not
      // mask which rows are blocking: the failures are collected and reported
      // together for a single revoke-and-retry decision.
      const rearms: EmergencyRearmEntry[] = [];
      const untrusted: BlockedContact[] = [];

      for (const row of rows) {
        try {
          const { rearms: built } = await buildEmergencyRearms(
            [{ emergencyAccessId: row.emergencyAccessId, granteeUserId: row.granteeUserId, waitTimeDays: row.waitTimeDays }],
            lang
          );
          rearms.push(...built);
        } catch (err) {
          if (isVaultError(err) && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
            untrusted.push({ id: row.emergencyAccessId, name: row.granteeName, email: row.granteeEmail });
          } else {
            throw err;
          }
        }
      }

      if (untrusted.length > 0) throw new UntrustedRearmError(untrusted);

      // After a council recovery, the released council credential is burned on the
      // same rewrite, renewed (or explicitly left).
      const body: VaultKeyringUpdateBody = {
        ...keyring,
        ...(rearms.length > 0 ? { emergency_rearms: rearms } : {}),
        ...(council?.councilRearm ? { council_rearm: council.councilRearm } : {}),
        ...(council?.councilDrop ? { council_drop: true } : {}),
      };

      // Covered route: sign the EXACT body we will send (same serialization the
      // request helper uses), so the proof's body digest matches, then attach it.
      const put = async (sent: VaultKeyringUpdateBody) => {
        const json = JSON.stringify(sent);
        const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'PUT', path: '/api/vault/keyring', body: json })) as {
          signature: string;
        };

        await withFreshIdToken(getIdToken, (idToken) => updateVaultKeyring(idToken, sent, signature));
      };

      try {
        await put(body);
      } catch (err) {
        // A council recovery released this vault's council credential and the user
        // left the forced change before it ended: whichever flow changes the phrase
        // next burns it, renewing the council's setup (or leaving it, when its
        // membership no longer verifies).
        if (council || !(err instanceof ApiError) || err.code !== API_ERROR_COUNCIL_REARM_REQUIRED) throw err;

        let renewal: Pick<VaultKeyringUpdateBody, 'council_rearm' | 'council_drop'>;
        try {
          const forMe = await withFreshIdToken(getIdToken, fetchCouncilForMe);
          renewal = {
            council_rearm: await councilVault.createEscrow(forMe.council!.council_id, forMe.council!.chain, lang, forMe.escrow!.record.roster_hash),
          };
        } catch {
          renewal = { council_drop: true };
        }

        await put({ ...body, ...renewal });
      }
    },
    [getIdToken, request, buildEmergencyRearms, councilVault]
  );

  /**
   * The granted contacts whose re-arm the vault would refuse, asked BEFORE a new
   * phrase is generated, so the user is never shown a phrase that cannot be
   * committed. Same condition as the vault's escrow build (a binding-verified
   * directory record whose identity the user explicitly trusted); the commit
   * still enforces it, for a status that changes in between.
   */
  const findBlockedContacts = useCallback(async (): Promise<BlockedContact[]> => {
    const { contacts } = await withFreshIdToken(getIdToken, (idToken) => fetchTrustedContacts(idToken));
    const rows = grantedRearmRows(contacts, Date.now());

    if (rows.length === 0) return [];

    const { users } = (await request(MSG_VAULT_FETCH_PUBLIC_KEYS, { userIds: [...new Set(rows.map((row) => row.granteeUserId))] })) as {
      users: Record<string, VaultRegisteredUser>;
    };
    const { fingerprints } = (await request(MSG_VAULT_GET_KNOWN_FINGERPRINTS)) as {
      fingerprints: Record<string, { fingerprint: string; status: 'unknown' | 'trusted' | 'refused' }>;
    };

    return rows
      .filter((row) => {
        const entry = users[row.granteeUserId];
        const known = fingerprints[row.granteeUserId];

        return !(entry?.verified && known?.status === 'trusted' && known.fingerprint === entry.identityFingerprint);
      })
      .map((row) => ({ id: row.emergencyAccessId, name: row.granteeName, email: row.granteeEmail }));
  }, [getIdToken, request]);

  /** Revoke the given relationships (used on the blocking contacts before a retry). */
  const revokeContacts = useCallback(
    async (ids: string[]): Promise<void> => {
      await withFreshIdToken(getIdToken, async (idToken) => {
        for (const id of ids) {
          await deleteEmergencyAccess(idToken, id);
        }
      });
    },
    [getIdToken]
  );

  return { commitKeyring, findBlockedContacts, revokeContacts };
}
