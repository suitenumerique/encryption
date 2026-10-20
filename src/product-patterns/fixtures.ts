// The people of every pattern, named after what they stand for in the flows:
// the viewer who shares, a recipient whose encryption is set up, one who has not
// set it up, members added before they had encryption (one has set it up since,
// one not yet), and a person invited by email who has no account.

export interface PatternUser {
  id: string;
  full_name: string;
  email: string;
}

export const me: PatternUser = { id: 'user-me', full_name: 'Camille Martin', email: 'camille.martin@example.org' };

export const withKeys: PatternUser = { id: 'user-alice', full_name: 'Alice Bernard', email: 'alice.bernard@example.org' };

export const withoutKeys: PatternUser = { id: 'user-bob', full_name: 'Bob Durand', email: 'bob.durand@example.org' };

export const pendingNowReady: PatternUser = { id: 'user-chloe', full_name: 'Chloé Petit', email: 'chloe.petit@example.org' };

export const pendingStillWaiting: PatternUser = { id: 'user-david', full_name: 'David Moreau', email: 'david.moreau@example.org' };

export const pendingWrapFailed: PatternUser = { id: 'user-emma', full_name: 'Emma Laurent', email: 'emma.laurent@example.org' };

export const invitedEmail = 'nadia.roux@example.org';
