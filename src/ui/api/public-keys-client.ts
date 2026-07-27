import { apiDefaults, authHeaders } from '@encryption/src/ui/api/client';
import {
  deleteApiPublicKeys,
  getApiPublicKeys,
  getApiPublicKeysNext,
  postApiPublicKeysRegisterComplete,
  postApiPublicKeysRegisterInit,
} from '@encryption/src/ui/api/generated/sdk.gen';
import type {
  GetApiPublicKeysData,
  PostApiPublicKeysRegisterCompleteData,
  PostApiPublicKeysRegisterInitData,
} from '@encryption/src/ui/api/generated/types.gen';

export async function fetchPublicKeys(query: GetApiPublicKeysData['query']) {
  const { data } = await getApiPublicKeys({ ...apiDefaults, query });

  return data;
}

export async function fetchNextKeyVersion(token: string) {
  const { data } = await getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(token) });

  return data;
}

export async function registerKeyInit(token: string, body: PostApiPublicKeysRegisterInitData['body']) {
  const { data } = await postApiPublicKeysRegisterInit({ ...apiDefaults, headers: authHeaders(token), body });

  return data;
}

export async function registerKeyComplete(token: string, body: PostApiPublicKeysRegisterCompleteData['body']) {
  const { data } = await postApiPublicKeysRegisterComplete({ ...apiDefaults, headers: authHeaders(token), body });

  return data;
}

export async function deletePublicKeys(token: string) {
  const { data } = await deleteApiPublicKeys({ ...apiDefaults, headers: authHeaders(token) });

  return data;
}
