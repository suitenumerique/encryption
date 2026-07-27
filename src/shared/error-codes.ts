/**
 * Error codes returned by the server API.
 * The frontend translates these via i18next at `errors.api.{CODE}`.
 * Never return human-readable messages from the server — only these codes.
 */
export const API_ERROR_INVALID_REQUEST = 'invalid_request';
export const API_ERROR_INTERNAL = 'internal_error';
export const API_ERROR_UNAUTHORIZED = 'unauthorized';
export const API_ERROR_FORBIDDEN = 'forbidden';

export const API_ERROR_EMAIL_CLAIM_REQUIRED = 'email_claim_required';

export const API_ERROR_FORBIDDEN_OTHER_USER = 'forbidden_other_user';
export const API_ERROR_RATE_LIMIT_KEYS = 'rate_limit_keys';
export const API_ERROR_RATE_LIMIT_CHALLENGES = 'rate_limit_challenges';
export const API_ERROR_NO_ACTIVE_KEY = 'no_active_key';
export const API_ERROR_CHALLENGE_NOT_FOUND = 'challenge_not_found';
export const API_ERROR_CHALLENGE_EXPIRED = 'challenge_expired';
export const API_ERROR_CHALLENGE_INVALID_RESPONSE = 'challenge_invalid_response';
export const API_ERROR_CONCURRENT_REGISTRATION = 'concurrent_registration';
export const API_ERROR_INVALID_KEY_BINDING = 'invalid_key_binding';
export const API_ERROR_INVALID_CHALLENGE_SIGNATURE = 'invalid_challenge_signature';
export const API_ERROR_KEY_VERSION_CONFLICT = 'key_version_conflict';
export const API_ERROR_INVALID_TIMESTAMP = 'invalid_timestamp';
export const API_ERROR_INVALID_PUBLIC_KEY = 'invalid_public_key';
export const API_ERROR_IDENTITY_TAKEN = 'identity_taken';
export const API_ERROR_ENCRYPTION_KEY_TAKEN = 'encryption_key_taken';
export const API_ERROR_NO_SERVER_VAULT = 'no_server_vault';
export const API_ERROR_VAULT_NOT_FOUND = 'vault_not_found';
export const API_ERROR_VAULT_CHALLENGE_NOT_FOUND = 'vault_challenge_not_found';
export const API_ERROR_VAULT_CHALLENGE_EXPIRED = 'vault_challenge_expired';
export const API_ERROR_VAULT_PROOF_INVALID = 'vault_proof_invalid';
export const API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID = 'vault_request_signature_invalid';
export const API_ERROR_VAULT_AUTH_BINDING_INVALID = 'vault_auth_binding_invalid';
export const API_ERROR_VAULT_KDF_PARAMS_INVALID = 'vault_kdf_params_invalid';
export const API_ERROR_VAULT_MANIFEST_INVALID = 'vault_manifest_invalid';
export const API_ERROR_VAULT_ITEM_OUT_OF_DATE = 'vault_item_out_of_date';
export const API_ERROR_VAULT_APPROVAL_NOT_FOUND = 'vault_approval_not_found';
export const API_ERROR_VAULT_APPROVAL_NOT_READY = 'vault_approval_not_ready';
export const API_ERROR_RATE_LIMIT_APPROVALS = 'rate_limit_approvals';

export const API_ERROR_EMERGENCY_NOT_FOUND = 'emergency_not_found';
export const API_ERROR_EMERGENCY_BAD_STATUS = 'emergency_bad_status';
export const API_ERROR_EMERGENCY_SELF_DESIGNATION = 'emergency_self_designation';
export const API_ERROR_EMERGENCY_ALREADY_EXISTS = 'emergency_already_exists';
export const API_ERROR_EMERGENCY_CONTACT_NOT_ONBOARDED = 'emergency_contact_not_onboarded';
export const API_ERROR_EMERGENCY_ESCROW_INVALID = 'emergency_escrow_invalid';
export const API_ERROR_EMERGENCY_REARM_REQUIRED = 'emergency_rearm_required';
export const API_ERROR_RATE_LIMIT_EMERGENCY = 'rate_limit_emergency';
