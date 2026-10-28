import { describe, expect, it } from 'vitest';

import { changeQuorum } from '@encryption/src/shared/council-quorum';

const roster = (n: number, threshold: number) => ({ threshold, members: Array.from({ length: n }) });

describe('changeQuorum', () => {
  it('asks for a strict majority, never fewer than the threshold', () => {
    expect(changeQuorum(roster(2, 1))).toBe(2);
    expect(changeQuorum(roster(3, 2))).toBe(2);
    expect(changeQuorum(roster(4, 2))).toBe(3);
    expect(changeQuorum(roster(5, 2))).toBe(3);
    expect(changeQuorum(roster(5, 4))).toBe(4);
    expect(changeQuorum(roster(12, 3))).toBe(7);
  });
});
