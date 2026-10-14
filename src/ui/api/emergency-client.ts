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

export async function searchEmergencyContact(idToken: string, email: string) {
  const { data } = await getApiEmergencyAccessSearch({ ...apiDefaults, headers: authHeaders(idToken), query: { email } });

  return data;
}

export async function fetchTrustedContacts(idToken: string) {
  const { data } = await getApiEmergencyAccessTrusted({ ...apiDefaults, headers: authHeaders(idToken) });

  return data;
}

export async function fetchGrantedVaults(idToken: string) {
  const { data } = await getApiEmergencyAccessGranted({ ...apiDefaults, headers: authHeaders(idToken) });

  return data;
}

export async function designateEmergencyContact(idToken: string, body: EmergencyDesignateBody, xSignature: string) {
  const { data } = await postApiEmergencyAccess({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), body });

  return data;
}

export async function acceptEmergencyDesignation(idToken: string, id: string) {
  const { data } = await postApiEmergencyAccessByIdAccept({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function rearmEmergencyEscrow(idToken: string, id: string, body: EmergencyRearmBody, xSignature: string) {
  const { data } = await postApiEmergencyAccessByIdRearm({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), path: { id }, body });

  return data;
}

export async function deleteEmergencyAccess(idToken: string, id: string) {
  const { data } = await deleteApiEmergencyAccessById({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function initiateEmergencyRecovery(idToken: string, id: string, xSignature: string) {
  const { data } = await postApiEmergencyAccessByIdInitiate({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), path: { id } });

  return data;
}

export async function cancelEmergencyRecovery(idToken: string, id: string) {
  const { data } = await postApiEmergencyAccessByIdCancel({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function rejectEmergencyRecovery(idToken: string, id: string) {
  const { data } = await postApiEmergencyAccessByIdReject({ ...apiDefaults, headers: authHeaders(idToken), path: { id } });

  return data;
}

export async function recoverEmergencyCapsule(idToken: string, id: string, xSignature: string) {
  const { data } = await postApiEmergencyAccessByIdRecover({ ...apiDefaults, headers: signedHeaders(idToken, xSignature), path: { id } });

  return data;
}
