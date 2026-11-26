# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

**A problem in the code** (this repository, whoever runs it): use GitHub's private
reporting, [Report a vulnerability](https://github.com/suitenumerique/encryption/security/advisories/new).
It reaches the maintainers, stays private until a fix exists, and gives you a channel
to follow up.

**A problem on a running instance**: contact its operator. Every deployment publishes
its own channel at `/.well-known/security.txt` on each of its domains. The instances
operated by the DINUM for La Suite numérique point to the DINUM vulnerability
disclosure programme, [vdp.numerique.gouv.fr](https://vdp.numerique.gouv.fr/p/Send-a-report?lang=en).

## What helps us

- The version: the `release` shown in the vulnerability, the image tag, or the commit.
- Steps that reproduce the problem, or the request and response involved.
- For anything about the cryptography or the iframe isolation, the browser and its
  version: the guarantees this service gives depend on browser behaviour (storage
  partitioning, secure contexts, Content Security Policy) as much as on its own code.

The security model, the threat model and what is deliberately out of scope are
described in [`architecture.md`](architecture.md) and in the
[integration guide](src/ui/docs/technical/integration.mdx).

## Disclosure policy

Working on a security issue in an open source project means fixing in the open while
attackers can read the same commits. Our policy:

1. The maintainers prepare and release the fix as usual (pull request, release), without
   describing the vulnerability in the commit or the release notes.
2. Once the fix is released and deployments have had time to update, the release notes
   are completed with the GitHub Security Advisory (GHSA) identifier and, when one was
   assigned, the CVE identifier.
3. The advisory is then published with credit to the reporter, unless they prefer not
   to be named.

Only the latest release is supported; there is no backport to earlier images.
