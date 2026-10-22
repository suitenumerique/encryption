// The people of the share modal patterns, named after what they stand for: the
// viewer, someone whose encryption is set up, someone who has not set it up, and
// members added before they had encryption (one has set it up since, one not yet).

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
