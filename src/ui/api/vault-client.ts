import { ApiError, apiDefaults, authHeaders, signedHeaders } from '@encryption/src/ui/api/client';
import {
  getApiVaultApprovalsByRequestId,
  getApiVaultApprovalsPending,
  getApiVaultMeta,
  postApiVault,
  postApiVaultApprovalsByRequestIdApprove,
  postApiVaultApprovalsRequest,
  putApiVaultKeyring,
} from '@encryption/src/ui/api/generated/sdk.gen';
import type {
  PostApiVaultApprovalsByRequestIdApproveData,
  PostApiVaultApprovalsRequestData,
  PostApiVaultData,
  PutApiVaultKeyringData,
} from '@encryption/src/ui/api/generated/types.gen';

/** Whether the account still holds a vault its recovery phrase could restore, dormant ones included. */
export async function hasRestorableVault(idToken: string): Promise<boolean> {
  try {
    await getApiVaultMeta({ ...apiDefaults, headers: authHeaders(idToken) });

    return true;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return false;

    throw err;
  }
}

export async function createVault(idToken: string, body: PostApiVaultData['body']) {
  const { data } = await postApiVault({ ...apiDefaults, headers: authHeaders(idToken), body });

  return data;
}

export async function updateVaultKeyring(idToken: string, body: PutApiVaultKeyringData['body'], xSignature: string) {
  const { data } = await putApiVaultKeyring({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), body });

  return data;
}

export async function requestDeviceApproval(idToken: string, body: PostApiVaultApprovalsRequestData['body']) {
  const { data } = await postApiVaultApprovalsRequest({ ...apiDefaults, headers: authHeaders(idToken), body });

  return data;
}

export async function fetchDeviceApproval(idToken: string, requestId: string) {
  const { data } = await getApiVaultApprovalsByRequestId({ ...apiDefaults, headers: authHeaders(idToken), path: { requestId } });

  return data;
}

export async function fetchPendingDeviceApprovals(idToken: string, xSignature: string) {
  const { data } = await getApiVaultApprovalsPending({ ...apiDefaults, headers: signedHeaders(idToken, xSignature) });

  return data;
}

export async function approveDeviceRequest(
  idToken: string,
  requestId: string,
  body: PostApiVaultApprovalsByRequestIdApproveData['body'],
  xSignature: string
) {
  const { data } = await postApiVaultApprovalsByRequestIdApprove({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { requestId },
    body,
  });

  return data;
}
