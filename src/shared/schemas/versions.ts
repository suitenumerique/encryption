import { z } from 'zod';

export const VersionsResponseSchema = z.object({
  vault: z.string(), // SRI hash of vault bundle
  ui: z.string(), // SRI hash of UI bundle
});

export type VersionsResponse = z.infer<typeof VersionsResponseSchema>;
