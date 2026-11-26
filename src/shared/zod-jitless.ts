import { z } from 'zod';

// Zod compiles object validators with `new Function` for speed. Under the CSP served
// to both documents that is refused, so the compilation can never happen in a browser
// anyway: Zod probes for it once, catches the refusal, and falls back to interpreting.
// The probe is harmless but it costs a CSP violation report on every page load, which
// would be permanent noise in any `securitypolicyviolation` reporting and could mask a
// real one. Telling Zod up front skips the probe entirely, because the probe sits
// behind `jit && allowsEval.value` and never runs once `jit` is false.
//
// Guarded on `document` so the server keeps its JIT, where there is no CSP and the
// compiled path is genuinely faster: ~0.9 vs ~4.2 microseconds per parse on a
// route-shaped schema. The alternative, granting `'unsafe-eval'`, would re-open
// `new Function` for the whole document to buy back those microseconds.
//
// Import this from EVERY module that builds a schema. Order inside the import list is
// irrelevant: a module's imports are all evaluated before its own body, so whichever
// schema module runs first has already applied this. That is what makes it immune to
// the import sorter reordering it.
if (typeof document !== 'undefined') {
  z.config({ jitless: true });
}
