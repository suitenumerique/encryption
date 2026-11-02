/** How the custodian space narrows a council's recovery requests; the server applies them. */
export const REQUEST_FILTERS = ['all', 'to-handle', 'awaiting_meeting', 'collecting', 'cooldown', 'released', 'stalled'] as const;
export type RequestFilter = (typeof REQUEST_FILTERS)[number];

/** The page sizes the request list accepts. */
export const REQUEST_PAGE_SIZES = [5, 10, 25, 50] as const;
