import { z } from 'zod';

// The context the client SDK hands the interface iframe on mount (via the
// MSG_INTERFACE_CONTEXT / MSG_INTERFACE_REQUEST_CONTEXT handshake). suiteUserId
// is always present; the per-flow blocks are set only for the flow that needs
// them. Recipient labels (email required, name optional) are display-only: the
// service is identity-opaque and never persists, syncs, or sends them anywhere.

export const recipientLabelSchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
});

// Concrete (zod-free) type on purpose: the SDK's generated client.d.ts is
// vendored verbatim by integrating products, and a `z.infer<...>` would drag a
// `zod` import into that public declaration (which consumers may not have). The
// schema stays the runtime source of truth; the assertion below fails to compile
// if the two ever drift.
export type RecipientLabel = { email: string; name?: string };

type _RecipientLabelMatchesSchema = z.infer<typeof recipientLabelSchema> extends RecipientLabel
  ? RecipientLabel extends z.infer<typeof recipientLabelSchema>
    ? true
    : never
  : never;
const _recipientLabelMatchesSchema: _RecipientLabelMatchesSchema = true;
void _recipientLabelMatchesSchema;

export const interfaceContextSchema = z.object({
  suiteUserId: z.string(),
  // Set only while the SDK-owned "verify recipients" overlay is open; carries
  // the full labeled recipient map (the interface surfaces only the blocked ones).
  verifyRecipients: z.object({ recipients: z.record(z.string(), recipientLabelSchema) }).optional(),
  // Set only while a /recipient-profile screen is open.
  recipientProfile: z.object({ userId: z.string(), label: recipientLabelSchema }).optional(),
  // Set when the SDK auto-opened the interface because the vault reported
  // actionable emergency-access state.
  emergencyPending: z
    .object({
      recovery: z.boolean(),
      invitation: z.boolean(),
    })
    .optional(),
});

export type InterfaceContext = z.infer<typeof interfaceContextSchema>;
