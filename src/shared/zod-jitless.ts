import { z } from 'zod';

// Zod compiles object validators with `new Function` for speed. Under the CSP served
// to both documents that is refused, so the compilation can never happen in a browser
// anyway: Zod probes for it once, catches the refusal, and falls back to interpreting.
// The probe is harmless but it costs a CSP violation report on every page load, which
// would be permanent noise in any `securitypolicyviolation` reporting and could mask a
// real one. Telling Zod up front skips the probe entirely, because `jit && allowsEval`
// short-circuits before `new Function` is reached.
//
// Guarded on `document` so the server keeps its JIT, where there is no CSP and the
// compiled path is genuinely faster.
//
// Import this from EVERY module that builds a schema. Order inside the import list is
// irrelevant: a module's imports are all evaluated before its own body, so whichever
// schema module runs first has already applied this. That is what makes it immune to
// the import sorter reordering it.
if (typeof document !== 'undefined') {
  z.config({ jitless: true });
}
