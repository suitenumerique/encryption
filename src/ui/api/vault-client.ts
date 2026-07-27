import { apiDefaults, authHeaders, signedHeaders } from '@encryption/src/ui/api/client';
import {
  getApiVaultApprovalsByRequestId,
  getApiVaultApprovalsPending,
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

export async function createVault(token: string, body: PostApiVaultData['body']) {
  const { data } = await postApiVault({ ...apiDefaults, headers: authHeaders(token), body });

  return data;
}

export async function updateVaultKeyring(token: string, body: PutApiVaultKeyringData['body'], xSignature: string) {
  const { data } = await putApiVaultKeyring({ ...apiDefaults, headers: signedHeaders(token, xSignature), body });

  return data;
}

export async function requestDeviceApproval(token: string, body: PostApiVaultApprovalsRequestData['body']) {
  const { data } = await postApiVaultApprovalsRequest({ ...apiDefaults, headers: authHeaders(token), body });

  return data;
}

export async function fetchDeviceApproval(token: string, requestId: string) {
  const { data } = await getApiVaultApprovalsByRequestId({ ...apiDefaults, headers: authHeaders(token), path: { requestId } });

  return data;
}

export async function fetchPendingDeviceApprovals(token: string, xSignature: string) {
  const { data } = await getApiVaultApprovalsPending({ ...apiDefaults, headers: signedHeaders(token, xSignature) });

  return data;
}

export async function approveDeviceRequest(
  token: string,
  requestId: string,
  body: PostApiVaultApprovalsByRequestIdApproveData['body'],
  xSignature: string
) {
  const { data } = await postApiVaultApprovalsByRequestIdApprove({
    ...apiDefaults,
    headers: signedHeaders(token, xSignature),
    path: { requestId },
    body,
  });

  return data;
}
