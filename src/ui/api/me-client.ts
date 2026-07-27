import { apiDefaults, authHeaders } from '@encryption/src/ui/api/client';
import { getApiMe } from '@encryption/src/ui/api/generated/sdk.gen';

export async function fetchMe(token: string) {
  const { data } = await getApiMe({ ...apiDefaults, headers: authHeaders(token) });

  return data;
}
