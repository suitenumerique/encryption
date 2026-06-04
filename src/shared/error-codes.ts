/**
 * Error codes returned by the server API.
 * The frontend translates these via i18next at `errors.api.{CODE}`.
 * Never return human-readable messages from the server — only these codes.
 */
export const API_ERROR_FORBIDDEN_OTHER_USER = 'forbidden_other_user';
export const API_ERROR_RATE_LIMIT_KEYS = 'rate_limit_keys';
export const API_ERROR_RATE_LIMIT_TRANSFERS = 'rate_limit_transfers';
export const API_ERROR_MISSING_FIELD = 'missing_field';
export const API_ERROR_UNAUTHORIZED = 'unauthorized';
export const API_ERROR_TRANSFER_CODE_INVALID = 'transfer_code_invalid';
export const API_ERROR_TRANSFER_CODE_EXPIRED = 'transfer_code_expired';
export const API_ERROR_TRANSFER_CODE_WRONG_USER = 'transfer_code_wrong_user';
export const API_ERROR_TRANSFER_CODE_ALREADY_USED = 'transfer_code_already_used';
export const API_ERROR_NO_ACTIVE_KEY = 'no_active_key';
export const API_ERROR_CHALLENGE_NOT_FOUND = 'challenge_not_found';
export const API_ERROR_CHALLENGE_EXPIRED = 'challenge_expired';
export const API_ERROR_CHALLENGE_INVALID_RESPONSE = 'challenge_invalid_response';
export const API_ERROR_CONCURRENT_REGISTRATION = 'concurrent_registration';
