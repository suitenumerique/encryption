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

export type RecipientLabel = z.infer<typeof recipientLabelSchema>;

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
