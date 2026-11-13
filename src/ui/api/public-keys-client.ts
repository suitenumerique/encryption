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

export async function fetchNextKeyVersion(idToken: string) {
  const { data } = await getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(idToken) });

  return data;
}

export async function registerKeyInit(idToken: string, body: PostApiPublicKeysRegisterInitData['body']) {
  const { data } = await postApiPublicKeysRegisterInit({ ...apiDefaults, headers: authHeaders(idToken), body });

  return data;
}

export async function registerKeyComplete(idToken: string, body: PostApiPublicKeysRegisterCompleteData['body']) {
  const { data } = await postApiPublicKeysRegisterComplete({ ...apiDefaults, headers: authHeaders(idToken), body });

  return data;
}

export async function deletePublicKeys(idToken: string) {
  const { data } = await deleteApiPublicKeys({ ...apiDefaults, headers: authHeaders(idToken) });

  return data;
}
