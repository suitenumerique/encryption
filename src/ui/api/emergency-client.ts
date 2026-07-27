import type { EmergencyDesignateBody, EmergencyRearmBody } from '@encryption/src/shared/schemas/emergency-access';
import { apiDefaults, authHeaders, signedHeaders } from '@encryption/src/ui/api/client';
import {
  deleteApiEmergencyAccessById,
  getApiEmergencyAccessGranted,
  getApiEmergencyAccessSearch,
  getApiEmergencyAccessTrusted,
  postApiEmergencyAccess,
  postApiEmergencyAccessByIdAccept,
  postApiEmergencyAccessByIdCancel,
  postApiEmergencyAccessByIdInitiate,
  postApiEmergencyAccessByIdRearm,
  postApiEmergencyAccessByIdRecover,
  postApiEmergencyAccessByIdReject,
} from '@encryption/src/ui/api/generated/sdk.gen';

export async function searchEmergencyContact(token: string, email: string) {
  const { data } = await getApiEmergencyAccessSearch({ ...apiDefaults, headers: authHeaders(token), query: { email } });

  return data;
}

export async function fetchTrustedContacts(token: string) {
  const { data } = await getApiEmergencyAccessTrusted({ ...apiDefaults, headers: authHeaders(token) });

  return data;
}

export async function fetchGrantedVaults(token: string) {
  const { data } = await getApiEmergencyAccessGranted({ ...apiDefaults, headers: authHeaders(token) });

  return data;
}

export async function designateEmergencyContact(token: string, body: EmergencyDesignateBody, xSignature: string) {
  const { data } = await postApiEmergencyAccess({ ...apiDefaults, headers: signedHeaders(token, xSignature), body });

  return data;
}

export async function acceptEmergencyDesignation(token: string, id: string) {
  const { data } = await postApiEmergencyAccessByIdAccept({ ...apiDefaults, headers: authHeaders(token), path: { id } });

  return data;
}

export async function rearmEmergencyEscrow(token: string, id: string, body: EmergencyRearmBody, xSignature: string) {
  const { data } = await postApiEmergencyAccessByIdRearm({ ...apiDefaults, headers: signedHeaders(token, xSignature), path: { id }, body });

  return data;
}

export async function deleteEmergencyAccess(token: string, id: string) {
  const { data } = await deleteApiEmergencyAccessById({ ...apiDefaults, headers: authHeaders(token), path: { id } });

  return data;
}

export async function initiateEmergencyRecovery(token: string, id: string, xSignature: string) {
  const { data } = await postApiEmergencyAccessByIdInitiate({ ...apiDefaults, headers: signedHeaders(token, xSignature), path: { id } });

  return data;
}

export async function cancelEmergencyRecovery(token: string, id: string) {
  const { data } = await postApiEmergencyAccessByIdCancel({ ...apiDefaults, headers: authHeaders(token), path: { id } });

  return data;
}

export async function rejectEmergencyRecovery(token: string, id: string) {
  const { data } = await postApiEmergencyAccessByIdReject({ ...apiDefaults, headers: authHeaders(token), path: { id } });

  return data;
}

export async function recoverEmergencyCapsule(token: string, id: string, xSignature: string) {
  const { data } = await postApiEmergencyAccessByIdRecover({ ...apiDefaults, headers: signedHeaders(token, xSignature), path: { id } });

  return data;
}
