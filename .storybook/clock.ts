const RealDate = Date;

// Moves the page's clock to `start` for one story, so a screen showing a date
// derived from "now" renders the same pixels on every run (visual snapshots
// otherwise report a change every day). The clock keeps ticking from there
// rather than being frozen: timers, countdowns and token expiry still see time
// pass. Fixtures must be built from the same `start`, not from `Date.now()` at
// import time, which runs before this is installed.
export function installClock(start: Date): () => void {
  const offset = start.getTime() - RealDate.now();

  class ShiftedDate extends RealDate {
    constructor(...args: unknown[]) {
      // Only `new Date()` reads the clock, every other form names its instant.
      super(...((args.length === 0 ? [RealDate.now() + offset] : args) as [number]));
    }

    static now(): number {
      return RealDate.now() + offset;
    }
  }

  globalThis.Date = ShiftedDate as DateConstructor;

  return () => {
    globalThis.Date = RealDate;
  };
}
