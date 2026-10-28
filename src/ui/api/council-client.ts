import { apiDefaults, authHeaders, signedHeaders } from '@encryption/src/ui/api/client';
import {
  getApiCouncilRecoveryRequestsByIdCustodian,
  getApiCouncilRecoveryRequestsByIdShares,
  getApiCouncilRecoveryRequestsMine,
  getApiCouncilsByCouncilIdSharesToCheck,
  getApiCouncilsForMe,
  getApiCouncilsMine,
  getApiCouncilsReshareBySessionIdBatch,
  postApiCouncilRecoveryRequests,
  postApiCouncilRecoveryRequestsByIdAbort,
  postApiCouncilRecoveryRequestsByIdContribute,
  postApiCouncilRecoveryRequestsByIdRefuse,
  postApiCouncilsByCouncilIdReshare,
  postApiCouncilsByCouncilIdSharesChecked,
  postApiCouncilsByCouncilIdVersionsByVersionSign,
  postApiCouncilsEscrow,
  postApiCouncilsReshareBySessionIdCancel,
  postApiCouncilsReshareBySessionIdKeys,
  postApiCouncilsReshareBySessionIdSubShares,
} from '@encryption/src/ui/api/generated/sdk.gen';
import type {
  GetApiCouncilRecoveryRequestsByIdCustodianResponses,
  GetApiCouncilRecoveryRequestsMineResponses,
  GetApiCouncilsForMeResponses,
  GetApiCouncilsMineResponses,
  PostApiCouncilRecoveryRequestsByIdContributeData,
  PostApiCouncilsByCouncilIdSharesCheckedData,
  PostApiCouncilsEscrowData,
  PostApiCouncilsReshareBySessionIdKeysData,
  PostApiCouncilsReshareBySessionIdSubSharesData,
} from '@encryption/src/ui/api/generated/types.gen';

export type CouncilsMine = GetApiCouncilsMineResponses[200];
export type CustodianCouncil = CouncilsMine['councils'][number];
export type CouncilRequestSummary = CustodianCouncil['requests'][number];
export type CouncilForMe = GetApiCouncilsForMeResponses[200];
export type MyCouncilRequest = NonNullable<GetApiCouncilRecoveryRequestsMineResponses[200]['request']>;
export type CustodianRequestDetail = GetApiCouncilRecoveryRequestsByIdCustodianResponses[200];

/**
 * A covered route takes an identity signature over the exact body sent, which
 * the vault produces: `sign` is that call, the body is serialized once here.
 */
export type RequestSigner = (method: string, path: string, body?: string) => Promise<string>;

export async function fetchMyCouncils(idToken: string) {
  const { data } = await getApiCouncilsMine({ ...apiDefaults, headers: authHeaders(idToken) });

  return data;
}

export async function fetchCouncilForMe(idToken: string) {
  const { data } = await getApiCouncilsForMe({ ...apiDefaults, headers: authHeaders(idToken) });

  return data;
}

export async function signCouncilVersion(idToken: string, sign: RequestSigner, councilId: string, version: number, signature: string) {
  const body = { signature };
  const path = `/api/councils/${encodeURIComponent(councilId)}/versions/${version}/sign`;
  const xSignature = await sign('POST', path, JSON.stringify(body));
  const { data } = await postApiCouncilsByCouncilIdVersionsByVersionSign({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { councilId, version },
    body,
  });

  return data;
}

export async function enrollCouncilEscrow(idToken: string, sign: RequestSigner, body: PostApiCouncilsEscrowData['body']) {
  const xSignature = await sign('POST', '/api/councils/escrow', JSON.stringify(body));
  const { data } = await postApiCouncilsEscrow({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), body });

  return data;
}

export async function askCouncilRecovery(idToken: string, ephemeralPublicKey: string) {
  const { data } = await postApiCouncilRecoveryRequests({
    ...apiDefaults,
    headers: authHeaders(idToken),
    body: { ephemeral_public_key: ephemeralPublicKey },
  });

  return data;
}

export async function fetchMyCouncilRequest(idToken: string) {
  const { data } = await getApiCouncilRecoveryRequestsMine({ ...apiDefaults, headers: authHeaders(idToken) });

  return data.request;
}

export async function refuseCouncilRequest(idToken: string, id: string) {
  const { data } = await postApiCouncilRecoveryRequestsByIdRefuse({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function fetchReleasedShares(idToken: string, id: string) {
  const { data } = await getApiCouncilRecoveryRequestsByIdShares({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function fetchCustodianRequest(idToken: string, id: string) {
  const { data } = await getApiCouncilRecoveryRequestsByIdCustodian({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function contributeToCouncilRequest(
  idToken: string,
  sign: RequestSigner,
  id: string,
  body: PostApiCouncilRecoveryRequestsByIdContributeData['body']
) {
  const xSignature = await sign('POST', `/api/council-recovery/requests/${id}/contribute`, JSON.stringify(body));
  const { data } = await postApiCouncilRecoveryRequestsByIdContribute({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { id },
    body,
  });

  return data;
}

export async function abortCouncilRequest(idToken: string, sign: RequestSigner, id: string) {
  const xSignature = await sign('POST', `/api/council-recovery/requests/${id}/abort`);
  const { data } = await postApiCouncilRecoveryRequestsByIdAbort({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), path: { id } });

  return data;
}

export async function startCouncilReshare(idToken: string, sign: RequestSigner, councilId: string, sourceVersion: number, helperSlots: number[]) {
  const body = { source_version: sourceVersion, helper_slots: helperSlots };
  const xSignature = await sign('POST', `/api/councils/${encodeURIComponent(councilId)}/reshare`, JSON.stringify(body));
  const { data } = await postApiCouncilsByCouncilIdReshare({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { councilId },
    body,
  });

  return data;
}

export async function fetchReshareBatch(idToken: string, sessionId: string) {
  const { data } = await getApiCouncilsReshareBySessionIdBatch({ ...apiDefaults, headers: authHeaders(idToken), path: { sessionId } });

  return data;
}

export async function uploadReshareKeys(
  idToken: string,
  sign: RequestSigner,
  sessionId: string,
  body: PostApiCouncilsReshareBySessionIdKeysData['body']
) {
  const xSignature = await sign('POST', `/api/councils/reshare/${sessionId}/keys`, JSON.stringify(body));
  const { data } = await postApiCouncilsReshareBySessionIdKeys({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { sessionId },
    body,
  });

  return data;
}

export async function uploadReshareSubShares(
  idToken: string,
  sign: RequestSigner,
  sessionId: string,
  body: PostApiCouncilsReshareBySessionIdSubSharesData['body']
) {
  const xSignature = await sign('POST', `/api/councils/reshare/${sessionId}/sub-shares`, JSON.stringify(body));
  const { data } = await postApiCouncilsReshareBySessionIdSubShares({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { sessionId },
    body,
  });

  return data;
}

export async function cancelCouncilReshare(idToken: string, sign: RequestSigner, sessionId: string) {
  const xSignature = await sign('POST', `/api/councils/reshare/${sessionId}/cancel`);
  const { data } = await postApiCouncilsReshareBySessionIdCancel({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { sessionId },
  });

  return data;
}

export async function fetchSharesToCheck(idToken: string, councilId: string) {
  const { data } = await getApiCouncilsByCouncilIdSharesToCheck({ ...apiDefaults, headers: authHeaders(idToken), path: { councilId } });

  return data;
}

export async function uploadSharesChecked(
  idToken: string,
  sign: RequestSigner,
  councilId: string,
  body: PostApiCouncilsByCouncilIdSharesCheckedData['body']
) {
  const xSignature = await sign('POST', `/api/councils/${encodeURIComponent(councilId)}/shares-checked`, JSON.stringify(body));
  const { data } = await postApiCouncilsByCouncilIdSharesChecked({
    ...apiDefaults,
    headers: signedHeaders(idToken, xSignature),
    path: { councilId },
    body,
  });

  return data;
}
