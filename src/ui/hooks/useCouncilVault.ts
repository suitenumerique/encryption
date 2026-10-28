import { useMemo } from 'react';

import type { MnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import {
  MSG_VAULT_COUNCIL_CHECK_ESCROW,
  MSG_VAULT_COUNCIL_CHECK_SHARES,
  MSG_VAULT_COUNCIL_COMPLETE_RECOVERY,
  MSG_VAULT_COUNCIL_CONTRIBUTE,
  MSG_VAULT_COUNCIL_CREATE_ESCROW,
  MSG_VAULT_COUNCIL_MARK_VERIFIED,
  MSG_VAULT_COUNCIL_REACTIVATE,
  MSG_VAULT_COUNCIL_REQUEST_KEY,
  MSG_VAULT_COUNCIL_RESHARE_BATCH,
  MSG_VAULT_COUNCIL_SIGN_ROSTER,
  MSG_VAULT_COUNCIL_START_REQUEST,
  MSG_VAULT_COUNCIL_VERIFY_ROSTER,
  MSG_VAULT_SIGN_REQUEST,
} from '@encryption/src/shared/constants';
import type {
  CouncilCheckBatch,
  CouncilCheckResultsBody,
  CouncilContributionBody,
  CouncilEscrowBody,
  CouncilEscrowRecordWire,
  CouncilReleasedShares,
  CouncilReshareBatch,
  CouncilReshareKeysBody,
  CouncilReshareSubSharesBody,
  RosterVersionWire,
} from '@encryption/src/shared/schemas/recovery-council';
import type { CustodianRequestDetail, RequestSigner } from '@encryption/src/ui/api/council-client';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';
import type { CouncilEscrowCheck, CouncilIdentity } from '@encryption/src/vault/operations/recovery-council';

/** The recovery council's vault operations, typed (all privileged: the interface's own). */
export function useCouncilVault() {
  const { request } = useEncryptionContext();

  return useMemo(
    () => ({
      sign: (async (method, path, body) => {
        const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method, path, body })) as { signature: string };

        return signature;
      }) satisfies RequestSigner,
      verifyRoster: (councilId: string, chain: RosterVersionWire[], anchorHash?: string) =>
        request(MSG_VAULT_COUNCIL_VERIFY_ROSTER, { councilId, chain, anchorHash }) as Promise<{ version: number } & CouncilIdentity>,
      markVerified: (councilId: string, chain: RosterVersionWire[]) =>
        request(MSG_VAULT_COUNCIL_MARK_VERIFIED, { councilId, chain }) as Promise<CouncilIdentity>,
      createEscrow: (councilId: string, chain: RosterVersionWire[], lang: MnemonicLanguage, anchorHash?: string) =>
        request(MSG_VAULT_COUNCIL_CREATE_ESCROW, { councilId, chain, anchorHash, lang }) as Promise<CouncilEscrowBody>,
      checkEscrow: (record: CouncilEscrowRecordWire, chain: RosterVersionWire[]) =>
        request(MSG_VAULT_COUNCIL_CHECK_ESCROW, { record, chain }) as Promise<{
          status: CouncilEscrowCheck;
          renewalDue: boolean;
          council: CouncilIdentity | null;
        }>,
      startRequest: () => request(MSG_VAULT_COUNCIL_START_REQUEST) as Promise<{ ephemeralPublicKey: string; fingerprint: string }>,
      requestKey: (serverFingerprint?: string | null) =>
        request(MSG_VAULT_COUNCIL_REQUEST_KEY, { serverFingerprint }) as Promise<{ ephemeralPublicKey: string; fingerprint: string } | null>,
      completeRecovery: (released: CouncilReleasedShares, idToken: string) =>
        request(MSG_VAULT_COUNCIL_COMPLETE_RECOVERY, { released, idToken }) as Promise<{
          publicKey: string;
          signaturePublicKey: string;
          isActiveVault: boolean;
          vaultCreatedAtMillis: number;
          contributors: Array<{ name: string | null; inPerson: boolean }>;
        }>,
      reactivate: (idToken: string) =>
        request(MSG_VAULT_COUNCIL_REACTIVATE, { idToken }) as Promise<{ publicKey: string; signaturePublicKey: string }>,
      contribute: (detail: CustodianRequestDetail, inPerson: boolean, meetingCode?: string) =>
        request(MSG_VAULT_COUNCIL_CONTRIBUTE, { detail, inPerson, meetingCode }) as Promise<CouncilContributionBody>,
      signRoster: (councilId: string, chain: RosterVersionWire[], proposal: RosterVersionWire) =>
        request(MSG_VAULT_COUNCIL_SIGN_ROSTER, { councilId, chain, proposal }) as Promise<{ signature: string }>,
      checkShares: (batch: CouncilCheckBatch) =>
        request(MSG_VAULT_COUNCIL_CHECK_SHARES, { batch }) as Promise<{ results: CouncilCheckResultsBody['results'] }>,
      reshareBatch: (batch: CouncilReshareBatch) =>
        request(MSG_VAULT_COUNCIL_RESHARE_BATCH, { batch }) as Promise<{
          keys: CouncilReshareKeysBody | null;
          subShares: CouncilReshareSubSharesBody | null;
        }>,
    }),
    [request]
  );
}
