# Security policy

This service holds users' private encryption keys. A vulnerability here is not a
degraded feature, it is a loss of confidentiality for everything the products
encrypted. Reports are read quickly and taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting on this
repository: the **Security** tab, then **Report a vulnerability**. It creates a
private thread with the maintainers and lets us issue a fix before anything is
public.

Please include what you need to make the report actionable: affected version or
commit, a description of the impact, and the steps to reproduce it. A working
proof of concept is welcome but never required to report.

We aim to acknowledge a report within 5 working days, and to agree a disclosure
timeline with you. We will credit you in the advisory unless you prefer otherwise.

## Scope

In scope, and of particular interest:

- anything that lets one user's key material reach another party;
- anything that lets the **server** read plaintext, private keys, or a backup
  passphrase, since the design is explicitly built so that a compromised server
  cannot;
- bypassing the vault's origin checks or the privileged-operation boundary
  (`PRIVILEGED_OPERATIONS`, `isInterfaceOrigin`);
- forging or replaying an identity binding, a key registration, or a
  proof-of-possession challenge;
- weaknesses in device transfer, emergency access, or the recovery kit;
- supply chain issues in this repository's build or release pipeline.

Out of scope: findings against the local development stack
(`docker-compose.yaml`, the bundled Keycloak realm, the demo products under
`src/demo/`), which exist only to run the project on a laptop and ship no
credentials of value.

## Verifying a release

Every image published by this repository carries a build provenance attestation,
signed through Sigstore with the release workflow's own identity and recorded in a
public transparency log. Verify it before deploying:

```bash
gh attestation verify oci://lasuite/encryption:<tag> \
  --repo numerique-gouv/encryption \
  --signer-workflow numerique-gouv/encryption/.github/workflows/ci.yml
```

An image pushed with a stolen registry token has no valid attestation for that
workflow and must be refused.

The image also carries an SBOM and full provenance:

```bash
docker buildx imagetools inspect lasuite/encryption:<tag> --format '{{ json .SBOM }}'
docker buildx imagetools inspect lasuite/encryption:<tag> --format '{{ json .Provenance }}'
```

Note what provenance does and does not prove: it proves the image was produced by
this workflow from this repository. It does not prove the source was benign. It is
the control against a stolen credential, not against a malicious commit.

## Supply chain

The measures protecting the build itself, and the reasoning behind each one, are
documented in [plan.md](./plan.md). In short: no dependency executes code at install
time, every dependency is registry-resolved and hash-verified, every GitHub Action is
pinned to a commit SHA, the release job is the only one that ever holds a credential,
and the complete route surface, the install-script list and the `node_modules/.bin`
table are committed snapshots that CI regenerates and diffs on every run.
