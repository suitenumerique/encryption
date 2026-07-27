# Encryption Service: Architecture

This is the reference for how the encryption service works: how products encrypt and share documents, and how each user's keys and trust state are stored and synchronized across their devices. It states what each party stores, how trust is established, and how conflicts and failures are handled.

The system gives each user an encrypted vault so that their keys and trust registry follow them onto every device, while document sharing works through a public directory of users' public keys.

## Contents

1. [Glossary](#1-glossary)
2. [System overview: who stores what](#2-system-overview-who-stores-what)
3. [Document sharing](#3-document-sharing)
4. [The synchronized vault](#4-the-synchronized-vault)
5. [Vault flows](#5-vault-flows)
6. [Conflict prevention and resolution](#6-conflict-prevention-and-resolution)
7. [Integrity model](#7-integrity-model)
8. [Failure handling](#8-failure-handling)
9. [Recovery and lifecycle policy](#9-recovery-and-lifecycle-policy)
10. [Why we model this on password managers](#10-why-we-model-this-on-password-managers)
11. [Threat model summary](#11-threat-model-summary)
12. [Emergency access (trusted contacts)](#12-emergency-access-trusted-contacts)

- [Appendix A: Migrating the OIDC provider (subs change)](#appendix-a-migrating-the-oidc-provider-subs-change)

---

## 1. Glossary

- **Product app**: the software the user sees (Docs, Drive, Meet). It runs on **its own web domain** (e.g. `docs.example.fr`), distinct from the encryption domains, and handles encrypted content without ever seeing private keys.
- **Product backend**: that software's server. It stores the encrypted documents and the application-level sharing table (who may open what).
- **Vault iframe** (`data.encryption.*`): an invisible, isolated frame loaded by the product. It holds the user's private keys and performs all crypto. The product talks to it only via `postMessage`.
- **Interface iframe** (`encryption.*`): the visible frame for onboarding, settings, and recovery.
- **Encryption server**: the central server. It hosts the public-key registry and the encrypted vault.
- **Public-key registry**: a **public** directory holding, per user, the encryption public key, the identity (signature) public key, a binding signature, and a version. Being public, it needs integrity (the binding signature), not confidentiality.
- **Vault**: a per-user encrypted container, decryptable only with the user's recovery phrase, synchronized through the server so it follows the user across devices. It holds the key pairs and the trust registry.
- **TOFU registry**: the record of each contact's fingerprint and its status: **unknown** (seen on first contact, recorded but not verified), **trusted**, or **refused** (the last two only from an explicit user decision). Sharing to an unknown contact is allowed; a later **change** to a recorded fingerprint is a mismatch that blocks. It is **sensitive** (your trust decisions and relationship graph), so it lives in the vault, never in clear on the server.
- **Vault item**: one logical record in the vault (one encryption key version, the identity key, or one TOFU entry), stored on the server as a single opaque ciphertext, one row per item.
- **VaultState**: the in-memory representation of all items on a device.
- **Recovery phrase (`R`)**: a machine-generated, high-entropy BIP-39 mnemonic; the user's only long-term secret. Shown once at onboarding, printed as the Recovery Kit, never displayed again, never stored by us.
- **KEK / VRK**: the Key-Encryption Key derived from `R` (Argon2id), which wraps the random Vault Root Key that actually encrypts the vault items.
- **Identity key**: the user's Ed25519 signature key pair; the stable identity whose fingerprint contacts verify out-of-band. It signs the vault manifest.
- **Device key**: a per-device key pair created on enrollment; caches the VRK at rest and authenticates that device's ongoing syncs.
- **Document key (DEK)**: the symmetric key (XChaCha20-Poly1305, 32 bytes) that encrypts one document.
- **Wrap / unwrap a key**: encrypt a document key to a recipient's encryption public key so only they can unwrap it.
- **Out-of-band-verified fingerprint**: a short digest of the identity key compared between two people over another channel (QR, spoken digits), impossible for a malicious server to forge.
- **Trusted computing base (TCB)**: the set of code that must be correct for every other guarantee to hold. Nothing protects you from a bug or a backdoor inside it, so the goal is to keep it as small and as tamper-evident as possible. Here it is the vault's served code (Section 11.4).
- **Alice and Bob**: in diagrams, Alice shares a document, Bob receives access.

---

## 2. System overview: who stores what

```mermaid
%%{init: {'theme':'base'}}%%
flowchart TB
  subgraph PROD["Product (product domain, e.g. docs.example.fr)"]
    PF["Product app<br/>(UI + client SDK)"]
    PB["Product backend<br/>encrypted documents<br/>+ sharing table (wrapped keys)<br/><b>DURABLE</b>"]
  end
  subgraph ENC["Encryption service (isolated domains)"]
    VF1["Vault iframe, device 1<br/>unlocked VaultState (in memory)"]
    VF2["Vault iframe, device 2<br/>unlocked VaultState (in memory)"]
    REG["Server: public-key registry (public)"]
    COF["Server: encrypted vault<br/>keys + identity + TOFU (opaque, per item)"]
  end
  PF -->|"postMessage (encrypt / decrypt)"| VF1
  PF -->|"HTTP: documents + wrapped keys"| PB
  VF1 -->|"read registry"| REG
  VF1 <-->|"sync vault"| COF
  VF2 <-->|"sync vault"| COF
  classDef durable fill:#e2f0d9,stroke:#3c763d,color:#000;
  classDef perm fill:#ffe2e2,stroke:#d33,color:#000;
  class PB perm;
  class COF durable;
```

|                                                                                     | Stored where                                                 | Confidential?                     |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------- |
| Public-key registry (encryption + identity public keys, binding signature, version) | Encryption server, **public**                                | No, integrity only                |
| Encrypted vault (key pairs + TOFU)                                                  | Encryption server, **opaque per-item ciphertext**            | Yes, server cannot read it        |
| Encrypted documents + sharing table (wrapped document keys)                         | Product backend, **durable**                                 | Documents and keys are ciphertext |
| Unlocked VaultState                                                                 | Vault iframe, **in memory** while unlocked                   | n/a                               |
| Wrapped VRK cache                                                                   | Vault iframe, **at rest** under a non-extractable device key | Yes                               |

The encryption server is a **blind store**: it reads routing metadata (who, which item, how recent) but never any content. This is the same posture as Bitwarden's server, plus one addition: we **sign** what we store so integrity does not depend on trusting the server (Section 7).

### 2.1 Internal user id: identity outlives the OIDC provider

Products and the login flow speak the OIDC `sub`. That value is not stable over the life of a deployment since an organization can replace its identity provider, and the new provider mints new subs for the same humans. Meanwhile this service embeds a user identifier in places no data migration can ever rewrite: inside Ed25519-signed payloads (key binding, identity continuity, request proofs), inside sealed `tofu:<userId>` vault items pinned by the signed manifest, and as cache keys on every enrolled device.

The canonical identifier is therefore a service-minted, immutable UUID (`users.id`), created at first contact and used everywhere past the auth boundary: signatures, TOFU, foreign keys, caches, the directory. OIDC credentials map to it through the `oidc_accounts` table, one row per unique `(issuer, sub)` pair. A provider migration becomes a plain data operation on that mapping table (a new row pointing at the same user, attached automatically by the verified-email fallback or manually by the operator) while every signature and sealed item stays valid. Directory resolution of a sub is scoped to the currently configured issuer, always: matching retired-issuer rows would be fail-open (on a cross-issuer sub collision the directory could return another human's public key, the one wrong answer a key directory must never give), so after a cutover a not-yet-relinked user simply shows as having no keys until their first post-cutover login. Retired rows are still never deleted; they remain as an audit trail and as raw material for operator merge tooling, and `disabledAt` blocks authentication with a retired provider.

Products never see internal ids. The SDK speaks subs end to end, and the vault translates at its boundary: the directory accepts `subs=` lookups, while TOFU and all persistence key on the internal id. The principle: **subs exist only at the two authentication boundaries** (JWT verification on the server, `setAuthContext` in the SDK); everything past those points speaks internal ids.

| Layer                                                              | Identifier           | Notes                                                                                   |
| ------------------------------------------------------------------ | -------------------- | --------------------------------------------------------------------------------------- |
| Signed payloads (binding, continuity, request proof)               | internal id          | the whole point: signatures survive provider changes                                    |
| All DB `user_id` columns                                           | internal id (FK)     | referential integrity for free                                                          |
| Sealed vault items (`tofu:<id>`), TOFU map keys                    | internal id          | trust decisions survive provider changes                                                |
| IndexedDB vault-cache row key, Web Locks names                     | internal id          | plus a small local sub-to-id alias store                                                |
| Directory records returned to clients                              | internal id          | responses echo the queried sub for correlation                                          |
| JWT `sub`                                                          | resolved at boundary | `(iss, sub)` looked up in `oidc_accounts`; request proofs sign the internal id directly |
| SDK own-user init (`setAuthContext`)                               | sub                  | resolved once via the fallback chain below                                              |
| SDK product-facing operations (recipients, fingerprints, profiles) | sub                  | the ONLY id products ever handle; the vault translates at its boundary                  |

**How the vault resolves the caller's own sub**: in-memory map, then the IndexedDB alias store (written alongside the vault cache, so a cached vault always resolves offline), then an unauthenticated registry lookup by sub. The interface uses the same chain through a privileged `resolve-user` operation, so an onboarded user's settings page works even with an expired OIDC session; only a never-onboarded user falls back to the authenticated `GET /api/me` (which mints the user row), after which the interface declares the id in its postMessage envelope and the vault, which adopts a declared internal id from privileged interface-origin callers only, persists the sub-to-id alias for the next visit. Recipient subs are resolved through the same batched directory fetch the operation already makes for keys and trust, so translation adds no round-trip. The alias store is metadata, never a trust input: a wrong alias can only cause a cache miss or a failed sync, never a wrong trust or decryption outcome (trust reads the sealed TOFU store, and every server call is independently authenticated).

`users.email` is the one piece of personal data attached to the account, and it is **required at first contact**: minting an account needs an address, because it is the only notification channel (security alerts, emergency access) and the only automatic continuity anchor across a provider migration. The address is read from the access-token claims, and when they carry none (some providers, only serve email from the userinfo endpoint) the server falls back to calling the issuer's userinfo endpoint with the presented access token (signed `application/jwt` responses are verified against the issuer JWKS); only if both yield nothing is the login rejected (`email_claim_required`). A **known** credential authenticates without any email at all — the requirement exists to seed the account, not to gate every request. Only provider-verified addresses qualify unless the deployment sets `OIDC_ACCEPT_UNVERIFIED_EMAIL`. The column is deliberately not unique: one address can legitimately end up on two accounts over time (a recycled corporate address, a homonym hired years later gets the released address while the departed user's account remains). The email fallback accounts for that: it links a new credential only when the address matches exactly one user AND that user was seen within the last year; a dormant match is treated as a probably-recycled address and gets a fresh account instead, leaving any merge to a deliberate operator action.

---

## 3. Document sharing

Each document has its own symmetric key. Sharing wraps that key to the recipient's encryption public key and stores the wrapped copy in the product's sharing table; reading unwraps it with the recipient's private key.

### 3.1 Share: Alice grants Bob access

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant PA as Product app (Alice)
  participant VA as Vault iframe (Alice)
  participant REG as Server registry
  participant PB as Product backend
  Note over VA: already holds the document key<br/>(unwrapped earlier with her private key)
  PA->>VA: share-keys (recipient: Bob)
  VA->>REG: request Bob's registry record
  REG-->>VA: Bob's encryption public key + binding signature
  Note over VA: verify binding signature (Ed25519)<br/>and out-of-band-verified fingerprint (TOFU)
  VA->>VA: wrap the document key to Bob's public key
  VA-->>PA: wrapped key for Bob
  PA->>PB: store wrapped key (document, Bob)
  Note over PB: durable sharing table (product side)
```

### 3.2 Read: Bob opens the document

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant PB2 as Product app (Bob)
  participant BK as Product backend
  participant VB as Vault iframe (Bob)
  PB2->>BK: request encrypted document + wrapped key for Bob
  BK-->>PB2: encrypted document + wrapped key
  PB2->>VB: decrypt-with-key (document, wrapped key)
  Note over VB: unwrap the key with Bob's private key,<br/>then decrypt the document
  VB-->>PB2: plaintext document
```

### 3.3 Backend request authorization and its trust boundary

A product backend can verify that a request acting on an encrypted document really comes from the user the document was shared with. It records, per share, the recipient's encryption-key **version** (an integer). To authorize a later request, it fetches from the registry the identity that this version is bound to and checks the request's signature against it. A legitimately rotated identity is accepted through the **continuity chain** (a successor identity carries a `continuitySignature` by its predecessor); a fresh, unlinked identity is not.

This check is **defense in depth on top of OIDC**. OIDC already authenticates the request as the user. The identity signature adds a cryptographic assurance that survives a **stolen access token**: a stolen token alone cannot produce the identity signature, and cannot register a continuity-linked successor (that needs the previous identity's private key, which never leaves the client), so it cannot silently act on the user's existing documents and can never read them.

**Trust boundary, stated plainly.** The backend **trusts the registry** for this lookup. It does not keep its own first-seen trust store per user, so a registry that is itself compromised could return a substituted identity and the backend would accept it. That is a deliberate limit: defending a product backend against a fully compromised registry _and_ a stolen token at once is out of scope, and cryptography cannot bootstrap trust from nothing. What still holds under a compromised registry is narrow but real: private keys never touch the server, so no registry compromise can **decrypt** content. At worst it enables impersonation or reshuffled shares over data that stays unreadable. The residual trust roots are therefore explicit and small: **OIDC for authentication, and the registry for the identity lookup**, with the continuity chain and the out-of-band fingerprint the tools that reduce, not eliminate, that registry trust.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant U as User (client)
  participant P as Product backend
  participant REG as Registry
  Note over P: recorded at share time, doc D wrapped for the user's enc-key v40
  U->>P: request on D, signed by the current identity
  P->>REG: fetch the identity bound to (user, enc-key v40)
  REG-->>P: identity I + binding signature (plus continuity links if rotated)
  Note over P: verify binding (v40 belongs to I)<br/>verify the request signature chains from I<br/>(I itself, or a continuity-signed successor)
  alt signature chains from the pinned identity
    Note over P: authorize the operation
  else fresh or unlinked identity, e.g. a stolen-token reset
    Note over P: reject as abnormal, cannot act on D
  end
```

### 3.4 Identity continuity in client trust (TOFU)

A client keeps a trust decision per contact, keyed on that contact's **identity fingerprint**. On first contact the fingerprint is **recorded as `unknown`** (seen, not verified) and **sharing is allowed**: there is deliberately **no trust-on-first-use** (the contact is not marked `trusted`), but neither is the share blocked. Recording the fingerprint is what lets a later change be caught. Marking a contact `trusted` (or `refused`) is only ever an **explicit user decision** (verify the fingerprint out-of-band, then accept). What is fail-safe is any **change**: a new fingerprint for a **recorded** contact is surfaced as a **mismatch**, which blocks the share and prompts the user to re-verify out-of-band. This is what detects an attacker who reset a victim's account into a new identity, and what detects a registry that substituted a key. A first encounter is not treated as an attack; a change to a known contact is.

The per-contact trust status is a small state machine, and every edge into `trusted` is an explicit human decision:

```mermaid
%%{init: {'theme':'base','themeVariables':{'fontSize':'15px','primaryColor':'#3b5bdb','primaryTextColor':'#fff','primaryBorderColor':'#2942b8','lineColor':'#5b6ee0','tertiaryColor':'#fff','labelBackgroundColor':'#ffffff','edgeLabelBackground':'#ffffff','transitionColor':'#5b6ee0','transitionLabelColor':'#33406b','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800'},'themeCSS':'.edgeLabel p{background-color:#fff;padding:4px 10px;border-radius:5px;margin:0;} .edgeLabel .labelBkg{background:transparent;} .statediagram-state .nodeLabel p{font-size:15px;padding:5px 12px;margin:0;}','stateDiagram':{'nodeSpacing':70,'rankSpacing':110,'useMaxWidth':true}}}%%
stateDiagram-v2
  direction LR
  [*] --> unknown: first encounter
  unknown --> trusted: verify out-of-band,<br/>then accept
  unknown --> refused: refuse
  trusted --> mismatch: new fingerprint
  refused --> mismatch: new fingerprint
  mismatch --> trusted: continuity walk<br/>reaches the pinned identity
  mismatch --> refused: same walk,<br/>refusal carried forward
  mismatch --> unknown: walk fails
  note right of unknown
    Fingerprint recorded,
    sharing allowed, but NEVER
    trusted on first use: only an
    explicit user decision leaves
    this state.
  end note
  note right of mismatch
    Sharing is BLOCKED here.
    The walk is bounded by
    MAX_CONTINUITY_HOPS and reads
    server data only, so a registry
    can degrade a contact to unknown,
    never forge an upgrade to trusted.
  end note
```

The continuity chain lets a **legitimate** rotation pass without re-verification: the client walks from the contact's current identity back toward the one it trusts, checking at each hop that the newer identity carries a valid `continuitySignature` from its predecessor, and only then carries the old trust status forward to the new fingerprint. This does **not** weaken the detection above, because forging any link requires that predecessor's **private key**, which never touches the server. A compromised registry can only **withhold or roll back** links, whose fail-safe effect is to fall back to unknown and force re-verification, never a false upgrade to trusted. A refused contact is stuck the same way: hiding the link makes them merely unknown (a fresh decision), not trusted, and they cannot fabricate a link from some other trusted identity. So continuity in TOFU propagates trust only along a chain the legitimate key holder actually signed, and stays safe against a database compromise.

The resolution happens **inside the normal fingerprint check**, not as a separate call. When a provided fingerprint mismatches a pinned one, the vault fetches that contact's continuity chain from the registry itself (`GET /api/public-keys/:userId/continuity`, public directory data needing no auth) and walks it: it verifies each link's signature and contiguity, and stops as soon as a link's predecessor is the identity it pinned, re-pinning the current fingerprint and keeping the old status. The walk is bounded by a shared hop cap (`MAX_CONTINUITY_HOPS`): a contact that rotated more times than that since the last verification, or a registry serving a longer fabricated chain, falls back to a fresh out-of-band check. No continuity data crosses the postMessage boundary, so products never handle it. Multiple rotations therefore resolve across several hops in a single check, and the cross-signing columns are the only registry data the walk relies on.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant C as Client (Alice)
  participant REG as Registry
  Note over C: locally trusted, contact Bob equals fingerprint B<br/>a new fingerprint A just mismatched
  C->>REG: fetch Bob's continuity chain (current identity first)
  REG-->>C: chain of links, each identity plus its predecessor and cross-signature
  loop each link, back toward B, up to the hop cap
    Note over C: verify the cross-signature and contiguity<br/>stop when a link's predecessor equals stored B
  end
  alt a valid chain reaches B within the cap
    Note over C: carry B's trust status forward to A<br/>no out-of-band re-verification needed
  else chain broken, absent, or over the cap
    Note over C: treat A as unknown<br/>ask the user to re-verify out-of-band
  end
```

### 3.5 Key registration: dual-key proof of possession

Before a key pair enters the directory, the client must prove it holds **both** private keys, and the record's identity binding must be internally coherent. This is the anti-impersonation core: it is what stops anyone (including a malicious server) from publishing a key they do not control, or claiming another user's key. It runs as two phases, `init` then `complete`.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant V as Vault iframe (holds both private keys)
  participant API as Encryption server
  Note over V: binding = sign(identity, {version, createdAt, encKey, idKey, userId})
  V->>API: POST register/init {encKey, idKey, version, createdAt, binding}
  Note over API: verify the binding signature and the timestamp skew<br/>encapsulate X-Wing to encKey, shared secret ss<br/>store expectedHmac = HMAC(ss, challengeId)
  API-->>V: {challengeId, ciphertext}
  Note over V: ss = decapsulate(ciphertext, encSecret), proves the ENCRYPTION key<br/>response = HMAC(ss, challengeId)<br/>challengeSig = sign(identity, challengeId), proves the IDENTITY key
  V->>API: POST register/complete {challengeId, response, challengeSig}
  Note over API: response equals expectedHmac, encryption-key proof<br/>challengeSig verifies under idKey, identity-key proof
  alt both proofs pass and the record is coherent
    Note over API: enforce version equals max plus 1 (monotonic, counts disabled)<br/>reject if encKey or idKey already belongs to ANOTHER user<br/>reactivate if already registered, else insert and activate
    API-->>V: 200 registered
  else a proof fails or the key is already taken
    API-->>V: reject (400 or 409)
  end
```

The two proofs are independent and both required: decapsulating the X-Wing ciphertext proves the **encryption** private key, and signing the server-issued challenge id proves the **identity** private key. The binding signature (verified at `init`) proves the encryption key was chosen by the holder of the identity key, and because `version` and `createdAt` are inside it, the server cannot silently renumber or backdate a record. The `complete` writes run in one Serializable transaction so two devices racing for the same next `version` cannot both succeed. A registration record is immutable: restoring an already-registered key **reactivates** its existing row rather than minting a new version. This is the same flow the atomic onboarding (5.1) folds into its bootstrap transaction, and it is what a re-onboard after a reset re-runs at `max + 1`.

---

## 4. The synchronized vault

### 4.1 What syncs

```
VaultState {
  schema: 1
  identities:     [ { generation, algo, sigPublicKey, sigSecretKey, createdAt } ]   // grow-only, immutable
  encryptionKeys: [ { version, algo, publicKey, secretKey, createdAt } ]            // grow-only, immutable
  active:         { identityGen, encKeyVersion }                                     // pointer to the current key
  tofu:           { [remoteUserId]: { fingerprint, status, revisionDate, deleted? } }// the only mutable data
}
```

- **Keep every key generation**, not just the current one: a device must _decrypt_ content wrapped under an old key while _encrypting_ under the active one. Old versions are immutable, so keeping them costs a few KB.
- **No cached "known public keys."** A TOFU entry is just `{ fingerprint, status }` keyed by `remoteUserId`; the actual public keys are fetched fresh from the registry and re-verified on use. The fingerprint plus the userId is all we need to remember a trust decision.
- **TOFU is the only mutable, conflict-prone state**: everything else is append-only. This is what makes conflict handling tractable (Section 6).

Each item's decrypted payload and each server row are validated against a **Zod schema** after decryption, matching the project convention in `src/shared/schemas`. AEAD already prevents tampering; Zod guards against bugs and schema drift.

### 4.2 Key hierarchy and the unlock secret

Bitwarden's master password does two jobs, authenticate and unlock, which forces it to be memorable, hence weak. We split those jobs: **OIDC authenticates**, and the vault's unlock secret only _unlocks_. That frees the unlock secret to be **machine-generated and high-entropy**, which is what defeats an offline attack on a stolen or leaked blob without needing 1Password's separate "Secret Key."

```
recovery phrase R          (generated, BIP-39, high entropy, the only long-term secret)
      │  Argon2id(R, salt = userId)        # salt is not secret; the server never runs this
      ▼
   KEK
      ├── seal → wrappedVRK                 # VRK is random; the KEK only wraps it
      └── HKDF(KEK, "vault-auth") → authKey (Ed25519)   # proof-of-passphrase, cold fetch only

   VRK  ──seal each item──▶  vault items (one opaque ciphertext each, on the server)
```

- **The recovery phrase is generated, never user-chosen.** No low-entropy fallback and therefore no "Secret Key" bolt-on: a high-entropy `R` already makes a downloaded blob unbruteforceable. Imposing generation guarantees that property for every user.
- **Argon2id** via libsodium `crypto_pwhash`. Because `R` is high-entropy, the KDF is defense-in-depth (it rate-limits online guessing and standardizes derivation), not the load-bearing barrier.
- **The salt is `userId`** (the stable OIDC `sub`). A salt is not a secret: public source code is irrelevant, and only the client ever runs the KDF, so there is no server-side check that needs it. Its jobs are per-user uniqueness and anti-precomputation, both satisfied by `userId`. A malicious server that tampered with a salt would only cause the client's KEK to be wrong and the AEAD unwrap to fail, a detectable denial of service, not a confidentiality break. (A random stored salt is an equally valid alternative with no security difference.)
- **The VRK indirection** (a random key wrapped by the KEK, mirroring Bitwarden's user key) makes two operations cheap: changing the passphrase re-wraps only the VRK, and enrolling a second device forwards the VRK wrapped to that device's key.

**What "rotation" means here.** A passphrase change re-wraps the VRK only. An encryption-key rotation _appends_ a new key version and re-encrypts nothing (old versions are kept for decryption). The VRK itself is only ever rotated if it is believed leaked, and only that rare case re-encrypts the items. Ordinary use never re-encrypts the vault.

**One vault, several credentials (LUKS-style keyslots).** The unlock material (the wrapped VRK, the passphrase-derived `authPublicKey` with its identity signature, the Argon2 params, the wordlist `lang`) lives in its own `VaultCredential` table rather than on the vault container: exactly one `primary` credential per vault (the owner's phrase, code-enforced), plus any number of `emergency` credentials, each owned by a trusted-contact relationship (Section 12) and each wrapping the SAME VRK under a different phrase. Emergency credentials are **dormant**: the unlock proof is never checked against them until that relationship's recovery is granted. `VaultKeyring` stays the vault container (identity, items, manifest, `disabledAt`); a credential is one way in.

### 4.3 Local storage and caching

Locally, the vault iframe keeps two things: a plain in-memory `VaultState`, and a durable cache holding the encrypted items, their revision, the manifest signature, and **the VRK wrapped by a non-extractable WebCrypto device key**.

Why cache the VRK rather than the passphrase: the passphrase (`R`) is the ultimate secret and also the printed recovery secret, so it is never persisted anywhere. The VRK is a derived key; caching it wrapped under a non-extractable device key means (a) we skip the deliberately-slow Argon2id every session, (b) we never re-prompt the mnemonic for routine use, including after the last tab is closed, and (c) script cannot exfiltrate the wrapping key. This is strictly safer than storing the phrase.

Two independent timers govern the cache:

- **Lock** (short, e.g. inactivity): clear the plaintext `VaultState` from memory. Unlock is instant: unwrap the cached VRK with the device key; no mnemonic needed.
- **De-enroll** (long, e.g. ~6 months): wipe the device-wrapped VRK, so the device must re-enroll via device-approval or the mnemonic. This bounds how long a stolen but still-logged-in device stays usable. The vault iframe enforces the check on load, so it triggers the next time any product embeds it.

---

## 5. Vault flows

Participants: **U** user, **P** product app, **UI** interface iframe, **V** vault iframe, **API** encryption server, **E** an enrolled device, **N** a new device.

### 5.1 Onboarding: vault creation

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant U as User
  participant UI as Interface iframe
  participant V as Vault iframe
  participant API as Encryption server
  U->>UI: Enable encryption
  UI->>V: generate-keys (privileged)
  Note over V: mint encryption key (X-Wing, v1)<br/>mint identity key (Ed25519, gen1)
  Note over V: generate recovery phrase R (BIP-39)<br/>KEK = Argon2id(R, userId)<br/>VRK = random 32B<br/>wrappedVRK = seal(VRK, KEK)<br/>authKey = HKDF(KEK,"vault-auth")<br/>authPubSig = sign(identity, authPubKey)
  Note over V: seal each item with VRK<br/>manifest = {rev:1, items[]}<br/>manifestSig = sign(identity, manifest)
  V->>API: GET /vault/bootstrap/challenge
  API-->>V: challenge (proof of possession of both keys)
  V->>API: POST /vault/bootstrap<br/>{registration + PoP, items, manifest, keyring}
  Note over API: verify PoP + binding signature<br/>commit registry + vault + keyring in ONE transaction<br/>(all-or-nothing)
  API-->>V: 200
  Note over V: enroll this device (device key)<br/>cache VRK wrapped by device key
  V-->>UI: ready + recovery phrase R (once)
  UI-->>U: show Recovery Kit (print), shown only now
```

Onboarding writes three things that must stay consistent: the public-key registration, the encrypted vault, and the keyring (the wrapped VRK plus the cold-fetch auth key). They are committed **atomically in a single server transaction** rather than as separate requests. A partial write would otherwise leave a harmful state, for example public keys registered so contacts wrap document keys to the user, but no keyring or vault backed up, so the data is unrecoverable if the device is lost, or a stored vault whose keyring never landed, which can never be unlocked. The preceding challenge fetch is read-only and safe to retry, and the commit is **idempotent** (registration reactivates rather than duplicates, and the vault write is keyed by content and revision), so a client that retries after a lost response completes cleanly.

### 5.2 Encrypt a document (product operation, no sync round-trip)

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant P as Product app
  participant V as Vault iframe (unlocked)
  P->>V: encrypt-with-key(plaintext[, recipient keys])
  Note over V: symKey = random<br/>ciphertext = secretbox(plaintext, symKey)<br/>wrap symKey (X-Wing) to each recipient
  V-->>P: ciphertext + wrapped keys
```

### 5.3 Cold unlock on a new device (mnemonic + proof-of-passphrase)

The only flow that uses the passphrase, when a device has nothing cached and no other device is available to approve it (otherwise use 5.6).

The proof-of-passphrase gates the **`wrappedVRK`**, not just the items. That placement is deliberate: the items are encrypted under the random VRK and are not brute-forceable, whereas `wrappedVRK = seal(VRK, Argon2id(R, ...))` is the only thing an attacker could grind against the passphrase, so it is what must not be handed to a bare token. The salt is `userId`, so no secret is fetched to derive the key; the only thing served before the proof is the account's **KDF cost variants** (non-sensitive numbers). They are needed because Argon2 params are stored **per vault**, so a vault created before the standard was raised keeps its own params: the client derives `authKey` for each distinct variant (cheapest first, almost always a single one) and retries the proof until a keyring verifies. No language is served or needed: `authKey` is derived from Argon2 over the phrase **string**, so the input validates typed words against every wordlist and the server only ever checks a signature. The `authPubKey` is a passphrase-derived verifier and is therefore **never** returned to a client; it is written at bootstrap and used only server-side to check the proof. As elsewhere, this gate is defense-in-depth: the high entropy of `R` is what actually protects a leaked `wrappedVRK`; the gate simply keeps that material away from a stolen token in the first place.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant U as User
  participant V as Vault iframe (new device)
  participant API as Encryption server
  V->>API: GET /vault/meta (non-sensitive)
  API-->>V: kdf_variants (Argon2 params per vault, cheapest first, usually one)
  U->>V: enter recovery phrase R (validated against every wordlist)
  V->>API: POST /vault/challenge
  API-->>V: nonce (valid 120s, consumed only on a match)
  loop each KDF variant until the proof verifies (usually the first)
    Note over V: salt = userId (no fetch needed)<br/>KEK = Argon2id(R, salt, variant)<br/>authKey = derive(KEK), proof = sign(nonce)
    V->>API: POST /vault/fetch {challengeId, proof}
    Note over API: verify proof vs EVERY keyring's authPubKey<br/>(a phrase can unlock a DORMANT vault, so not just the active one)<br/>no match: 401, releases NOTHING (not even wrappedVRK), challenge kept, try next variant
  end
  API-->>V: on a match: {wrappedVRK, items, manifest, manifestSig, rev, is_active}
  Note over V: (all variants 401 = wrong phrase, nothing released)
  Note over V: verify manifestSig vs trusted identity<br/>cross-check keys vs registry<br/>rev >= lastSeenRev (anti-rollback)
  alt is_active: the phrase unlocked the CURRENT vault
    Note over V: VRK = open(wrappedVRK, KEK), decrypt items,<br/>enroll device, cache VRK under device key — done
  else the phrase unlocked a DORMANT (superseded) vault
    Note over V: nothing cached yet, local state unchanged until the user confirms
    V->>U: modal: restore this older, superseded vault?<br/>(this demotes your current active vault)
    U->>V: confirm
    Note over V: confirm re-runs the WHOLE unlock above (fresh GET /vault/meta<br/>+ POST /vault/challenge, derive + prove per variant), now aimed at<br/>POST /vault/reactivate instead of /vault/fetch
    V->>API: POST /vault/reactivate {challengeId, proof}
    Note over API: verify proof vs every keyring, then activate this vault + its<br/>identity + key and DEMOTE the currently active one (kept, recoverable)
    API-->>V: {wrappedVRK, items, manifest, rev}
    Note over V: VRK = open(wrappedVRK, KEK), decrypt items,<br/>enroll device, cache VRK under device key
  end
```

The `is_active` flag drives the last fork. If the phrase unlocked the **current** vault, the client caches it and enrolls straight away. If it unlocked a **dormant** (superseded) vault, nothing is cached: the client shows a modal, and only if the user confirms does it call `/vault/reactivate`, which activates that vault and **demotes the currently active one** (the same phrase-authenticated switch §5.9 uses, and the mechanism behind recovering an older vault or reclaiming a vault after another device replaced the identity).

The candidate set the proof is checked against is every credential the phrase may legitimately unlock right now: the **primary** credential of each of the user's vaults (dormant vaults stay restorable by their own phrase), plus any **emergency** credential whose recovery is currently granted (Section 12). The response's `credential_type` tells the client which kind matched: an emergency match means the phrase was handed over by a trusted contact, and the interface locks into the forced phrase change of 12.5 before anything else.

### 5.4 Warm sync on an enrolled device

No passphrase, the device authenticates ongoing syncs with its **device key**. The everyday path.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant V as Vault iframe (enrolled)
  participant API as Encryption server
  Note over V: unwrap cached VRK with device key (silent)
  V->>API: GET /vault/revision
  API-->>V: accountRevision
  alt unchanged
    Note over V: nothing to pull
  else newer on server
    V->>API: GET /vault (challenge signed with device key)
    API-->>V: {items, manifest, manifestSig, rev}
    Note over V: verify manifestSig + rev >= lastSeenRev<br/>merge into VaultState
  end
```

### 5.5 Mutate the vault (with conflict handling)

Every local change goes through a single choke point (`applyAndSync`) so nothing bypasses sync: compute the change, re-sign the manifest, push **write-through** (commit to `VaultState` only once the server confirms). Mirrors Bitwarden's per-item optimistic concurrency.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant V as Vault iframe
  participant API as Encryption server
  Note over V: local change (e.g. TOFU: C → trusted)<br/>item.revisionDate = now<br/>re-sign manifest<br/>(not committed to VaultState yet)
  V->>API: PUT /vault/items/C {ciphertext, lastKnownRevisionDate}
  alt server copy not newer
    Note over API: stamp new revisionDate, bump accountRevision
    API-->>V: 200 OK
    Note over V: commit to VaultState + cache
  else server copy newer (> 1s)
    API-->>V: 409 out-of-date
    V->>API: GET /vault (latest)
    API-->>V: latest items + manifest
    Note over V: merge (keys: union, TOFU: LWW, refused/downgrade wins ties)<br/>re-apply local change
    V->>API: PUT /vault/items/C {ciphertext, lastKnownRevisionDate = new}
    API-->>V: 200 OK
  end
```

### 5.6 Add a device via approval (QR): the primary path

There are two ways to bring encryption onto a new device. When another device is at hand, this approval flow forwards the keys directly. When it is not, the user unlocks with the recovery phrase instead (5.3). This section is the with-another-device path. An already-enrolled, unlocked device forwards the **VRK** to a new device. The mnemonic is never involved here (it is not on the device to forward; the VRK is). The new device shows a **128-bit decimal fingerprint** of its ephemeral public key: as a QR to scan with a camera, and as digits to type when a camera is not available. The fingerprint is public, so capturing it is useless. It exists only so the enrolled device can confirm the server handed over the right key. 128 bits is deliberate: the ephemeral key and the whole exchange live for minutes and are used once, so there is no need for the recovery phrase's long-term, post-quantum 256-bit margin, and a shorter fingerprint keeps the typed fallback manageable.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant N as New device
  participant U as User
  participant E as Existing device (unlocked)
  participant API as Encryption server
  Note over N: generate ephemeral key pair<br/>fp = decimal128(SHA-256(devicePublicKey))
  N->>API: POST /vault/approvals/request {devicePublicKey}
  API-->>N: requestId (single-use, ~10 min TTL)
  N-->>U: show QR = fp (or reveal the fp digits to type)
  U->>E: scan the QR with a camera, or type the digits
  E->>API: GET /vault/approvals/pending
  API-->>E: pending {requestId, devicePublicKey}[]
  Note over E: pick the request whose key hashes to fp<br/>refuse if none match (server swapped the key)<br/>wrap VRK to that key
  E->>API: POST /vault/approvals/{requestId} {wrappedVRK_forN}
  N->>API: poll /vault/approvals/{requestId}
  API-->>N: {wrappedVRK_forN}
  Note over N: VRK = open(wrappedVRK_forN, devicePrivateKey)
  N->>API: pull sealed vault (items + manifest + revision)
  API-->>N: sealed vault
  Note over N: open every item with VRK<br/>cache VRK under a device key<br/>vault is now fully usable
```

The enrolled device fetches the full key from the server and wraps the VRK only after the out-of-band fingerprint matches, so a malicious server cannot substitute a key of its own: it would have to find a different key pair whose 128-bit fingerprint collides, which is infeasible (2^128). The forwarded capsule is the VRK alone. The new device then pulls the sealed vault and opens every item with that VRK, so it lands on a complete, usable vault rather than an orphaned key.

**What the return path does and does not guarantee.** The forwarded capsule (the VRK wrapped to the new device's ephemeral key) is unauthenticated public-key encryption: anyone holding that public key, the server included, can produce a valid wrapping. So the 128-bit fingerprint authenticates only the **new-to-enrolled** direction (the enrolled device wraps to the right key). It does not let the new device prove the returned VRK and vault are the real ones. A fully malicious server could therefore wrap its own VRK' and serve a self-consistent vault under an **attacker identity**, which a brand-new device, having no prior anchor, would adopt. This is not a pairing-specific weakness: it is the general case of an untrusted server substituting a user's identity (3.3, 3.4), and it is bounded from several directions, which is why we do not add a second out-of-band confirmation step:

- **An already-provisioned device cannot be silently flipped.** If the server tries to converge an enrolled device onto the fake vault, that device verifies the pulled manifest against the identity it **already trusts locally**; the attacker's signature does not match, so it fails closed (5.8, integrity error) instead of adopting. Fooling it would need the real identity's private key, which never left it.
- **The fake identity is inert to others unless the registry is also substituted.** Third parties can only encrypt to the new device if the attacker also publishes the fake identity in the public-key registry, and that publication is exactly what a contact's out-of-band fingerprint check (TOFU, 3.4) detects, and what an append-only registry trace would make **auditable** after the fact (see below).
- **The blast radius is new content only.** Existing documents stay under the real keys and remain unreadable to the fake identity. Only content the user creates on the freshly poisoned device is exposed, and it surfaces on first share via TOFU.

Turning an enrolled device's refusal into a guided "what happened / how to recover" flow, and telling this apart from a **legitimate** vault switch made on another device, is the reconciliation path (5.10). The net posture is worth stating plainly: being able to tamper with the server does **not** let it read content or silently take over a provisioned device. At most, and detectably, it can mislead a brand-new device or reshuffle data that stays unreadable.

> TODO: keep an **append-only trace** of registry writes (identity and key publications) so an identity substitution is auditable after the fact, not only detectable live by a contact's fingerprint check. The directory ledger is already permanent (5.9); this is about recording the write history in a form a user or auditor can review.

### 5.7 Change the recovery phrase

Cheap: re-wrap the VRK; the vault items are not touched. The previously printed Recovery Kit becomes invalid, so the user must re-print. One gate applies: when a trusted contact's recovery is currently granted on this vault, the keyring write must atomically carry a **burn + re-arm** payload for every granted escrow (the emergency phrase the contact saw dies, a fresh one replaces it), and the server rejects the write otherwise (12.5).

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant U as User
  participant V as Vault iframe (unlocked)
  participant API as Encryption server
  U->>V: rotate recovery phrase
  Note over V: R' = generate<br/>KEK' = Argon2id(R', userId)<br/>wrappedVRK' = seal(VRK, KEK')  (VRK unchanged)<br/>authKey' = HKDF(KEK',"vault-auth")<br/>authPubSig' = sign(identity, authPubKey')
  V->>API: PUT /vault/keyring {wrappedVRK', authPubKey', authPubSig', lang}
  Note over API: replace keyring (old R can no longer unlock)
  V-->>U: show new Recovery Kit (re-print), old print is void
```

### 5.8 Integrity failure handling

If the manifest signature does not verify, or the revision went backwards, the device refuses to apply the data and keeps its last-good state.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant V as Vault iframe
  participant API as Encryption server
  V->>API: GET /vault
  API-->>V: {items, manifest, manifestSig, rev}
  Note over V: verify manifestSig vs trusted identity<br/>rev >= lastSeenRev
  alt invalid signature or rolled-back revision
    Note over V: do NOT apply<br/>keep last-good cache
    V->>API: cross-check keys vs public registry (binding signatures)
    Note over V: raise integrity warning to the user<br/>offer: retry, or restore from recovery phrase
  else valid
    Note over V: apply and update lastSeenRev
  end
```

### 5.9 Lost access: disable, reactivate, or reset

A user who loses their recovery phrase and has no enrolled device de-onboards. This soft-disables the **identity and the vault keyring** (their rows stay, with `disabledAt` set); the **encryption key row is left valid**, so a later reactivation restores the _same_ key rather than rotating. Disabling targets the identity because the identity is what makes a user discoverable: the directory joins only _active_ identities, so a disabled identity disappears from the registry and others can no longer fetch its key to share with it, while the key itself remains intact for recovery. It is never a hard delete, so a stolen access token cannot destroy data, only hide it.

**The directory ledger is permanent.** Identities (their generation) and encryption-key versions, with their dates and `disabledAt`, are never purged. They are the audit trail ("on this date, this identity existed") and the source of the monotonic counters, so versions and generations never reset: a returning user's next key is `ledger max + 1`.

**The vault content is purgeable.** The wrapped VRK and sealed items are the only sensitive material (they hold private keys). A scheduled job deletes them once `disabledAt` exceeds the retention window of one year, which also bounds how long private keys sit at rest.

**Reactivation and reset.** Within the retention window, the correct recovery phrase reactivates the dormant vault: the phrase-derived auth key matches that vault's stored `authPublicKey`, which identifies the vault and proves ownership in one step. After the window, or when no disabled vault matches, the user onboards a fresh vault under a new identity and the old encrypted content is lost.

The vault's own lifecycle, with the two irreversible boundaries (the retention purge, and the fresh onboarding that follows it):

```mermaid
%%{init: {'theme':'base','themeVariables':{'fontSize':'15px','primaryColor':'#3b5bdb','primaryTextColor':'#fff','primaryBorderColor':'#2942b8','lineColor':'#5b6ee0','tertiaryColor':'#fff','labelBackgroundColor':'#ffffff','edgeLabelBackground':'#ffffff','transitionColor':'#5b6ee0','transitionLabelColor':'#33406b','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800'},'themeCSS':'.edgeLabel p{background-color:#fff;padding:4px 10px;border-radius:5px;margin:0;} .edgeLabel .labelBkg{background:transparent;} .statediagram-state .nodeLabel p{font-size:15px;padding:5px 12px;margin:0;}','stateDiagram':{'nodeSpacing':70,'rankSpacing':110,'padding':14,'useMaxWidth':true}}}%%
stateDiagram-v2
  direction LR
  [*] --> active: onboarding<br/>(identity + encryption key + vault keyring)
  active --> dormant: de-onboard<br/>(soft-disable identity and keyring, disabledAt set)
  dormant --> active: correct recovery phrase within the retention window<br/>(/vault/reactivate, same encryption key restored)
  dormant --> purged: retention job, disabledAt older than 1 year<br/>(wrapped VRK + sealed items deleted)
  purged --> active: onboarding a FRESH vault<br/>(new identity generation, old content lost)
  note right of purged
    The directory ledger is never purged: identity
    generations and key versions keep their dates and
    disabledAt forever, so the counters never reset
    (a returning user gets ledger max + 1).
    Emergency escrows follow the vault, so they stay
    exercisable while dormant and die only here (12.6).
  end note
```

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant U as User
  participant V as Vault iframe
  participant API as Encryption server
  U->>V: lost access, de-onboard
  V->>API: disable identity + vault keyring
  Note over API: soft-disable the IDENTITY + keyring (set disabledAt)<br/>encryption key row stays valid for later recovery<br/>directory joins only active identities, so it stops being listed<br/>a stolen access token can only hide data, never destroy it
  Note over API: ledger is permanent (identities + versions kept forever)<br/>scheduled purge removes only the vault content<br/>(wrappedVRK + sealed items) after disabledAt over 1 year
  alt within retention window, user re-enters the recovery phrase
    U->>V: recover with the recovery phrase
    Note over U,API: same frontend logic + endpoints as the §5.3 cold-unlock.<br/>The phrase resolves to the dormant vault, so its<br/>is_active=false path runs (modal, then /vault/reactivate).
  else phrase matches nothing or vault already purged
    V->>API: onboard a NEW identity + key + vault
    Note over API: generation = ledger max + 1, version = ledger max + 1<br/>counters never reset, old encrypted content is lost
  end
```

Two details the diagram compresses. **Nothing secret crosses the wire.** The device only ever sends a `challengeId` and an Ed25519 signature; the phrase, the KEK, and the VRK never leave it. The server stores each keyring's `authPublicKey` (a public key derived from the phrase) and the phrase-encrypted `wrappedVRK`, never the phrase or a hash of it, so a database thief learns nothing and the 256-bit phrase is unbruteforceable. **KDF params are per vault.** An older vault keeps the (weaker) Argon2 cost it was created with rather than today's, so the device cannot know which to use until it derives: it asks the server for the account's distinct variants (cheapest first) and retries the proof once per variant until one keyring verifies, almost always the first, since an account normally has a single variant. All attempts reuse one short-lived challenge, consumed only on a match and **not** invalidated on a wrong variant; that chaining is safe because every attempt still costs a full Argon2 derivation on the device and the phrase carries 256 bits of entropy. This walk-and-verify only happens on **cold restore**; an already-enrolled device that still holds its VRK syncs against the single active keyring directly (`/vault/items`, JWT-gated, no proof, no walk).

### 5.10 Reconciliation: when this device and the server disagree

§5.9 is the _cold_ case: a device with **no VRK**, holding only a recovery phrase. This section is the opposite: a device that **still holds its VRK** (cached under a non-extractable device key) but finds that the server no longer advertises its identity (disabled from another device) or advertises a **different** one (another device re-onboarded). The settings screen detects this by comparing its local identity fingerprint against the directory's active identity, and, since the two must agree before anything else works, gates on a reconciliation choice.

Two states, and the choices they offer:

- **Disabled elsewhere** (no active identity on the server): _reactivate this device_ (warm, below) or _de-onboard_ this device.
- **Diverged** (a different identity is active): _keep this device's identity_ (warm reactivate, which supersedes the other, and the other device must then reconcile in turn), _adopt the server's identity_ (discard the local keys and re-acquire the active one via a device or its recovery phrase), or _de-onboard_.

**Warm reactivation** is the key contrast with §5.9's cold path, and the reason it needs **no recovery phrase** is the **VRK**, not the keys. The VRK is what the passphrase originally produced (the phrase derives a KEK that unwraps the VRK), and this device already has it cached. Because the VRK is present, the device does not need the phrase to re-derive it: it opens its own vault with the cached VRK, and re-proves possession of the keys that vault contains (the same dual proof of possession used at registration). Holding the keys is itself a consequence of holding the VRK. The server's reactivate path then re-enables the identity and its encryption key, and flips this identity's vault keyring active (demoting any other), so identity and vault come back together. No `wrappedVRK` is released, because the device already has it.

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant U as User (device WITH keys)
  participant V as Vault iframe
  participant API as Encryption server
  Note over V: settings compares the local identity fingerprint<br/>against the directory's active identity
  API-->>V: no active identity (disabled elsewhere)<br/>OR a different active identity (diverged)
  Note over V: reconciliation gate: reactivate / adopt server / de-onboard
  U->>V: reactivate this device (no recovery phrase)
  Note over V: cached VRK opens the vault (the phrase is not needed<br/>to re-derive it), then re-sign a registration for its keys
  V->>API: register/complete (encryption-key PoP + identity-key PoP)
  Note over API: key already registered -> reactivate path<br/>re-enable identity + encryption key<br/>flip THIS identity's vault keyring active (demote others)
  API-->>V: reactivated (no wrappedVRK released, device already holds the VRK)
  Note over V: local vault unchanged, now back in sync with the server
```

---

## 6. Conflict prevention and resolution

The strategy is **prevention by data shape**: most of the vault cannot represent a conflict, so what is left to resolve is small and deterministic.

- **Encryption keys and identities are immutable and monotonic.** Two devices can only ever _add_ a new version or generation; merging is a **set union keyed by version/generation**: no conflict is representable. If two devices mint the same next `version`, the server's uniqueness constraint rejects the second, which re-pulls and picks `max+1`, the same optimistic-concurrency retry as any write.
- **TOFU entries are the only mutable items**, so the only place a genuine conflict can occur (device A trusts a contact, device B refuses the same contact). Resolution rules: a **fail-safe** refinement of Bitwarden's pure last-write-wins:
  1. Default: **last-write-wins by `revisionDate`**.
  2. **`refused` wins ties** and never loses to a same-or-older `trusted`.
  3. A **downgrade to `unknown`** (a fingerprint mismatch was detected) always wins, never silently re-trust a key another device flagged.
- **Deletion** of a TOFU entry uses a **tombstone** (a `deleted` marker carrying a `revisionDate`), not a user-facing trash. The tombstone participates in the same LWW so a stale device cannot resurrect a forgotten contact. We do **not** implement Bitwarden's soft-delete / Trash: that is a product feature we do not need; a tombstone is the minimum required for merge correctness.

Because the merge is **deterministic, commutative, and idempotent**, every device converges to the same state regardless of ordering, and the "re-pull, merge, retry" loop after a 409 is always safe to repeat.

Where we diverge from Bitwarden, stated plainly: Bitwarden's server can read each item's `revisionDate` and adjudicate last-write-wins itself, and its clients never merge. Our server is fully blind, so per-item concurrency is still enforced server-side on the opaque `revisionDate` column, but the **merge on a 409 happens on the client**. We accept this because the only mergeable data is the tiny, deterministic TOFU map; keys never merge.

---

## 7. Integrity model

Bitwarden does not sign vault items, it relies on transport auth and trusts the server for integrity. We do not, because our threat model includes a compromised server.

Alongside the items we store a **manifest**:

```
manifest = {
  revision,                 // monotonic
  identityGen,              // which identity generation signed, advisory hint only
  items: [ { id, type, contentHash, revisionDate } ],
}
manifestSig = Ed25519_sign(identitySecretKey, canonical(manifest))
```

A consuming device verifies, in order:

1. `manifestSig` against the **locally-trusted identity public key**, not whatever the server labels. `identityGen` is only a hint for _which_ key to expect; the trust anchor is the identity the device already holds (verified out-of-band and/or cross-checked against the public registry). A server that rewrites `identityGen` gains nothing, because it cannot produce a signature under a key it does not hold.
2. Every item's `contentHash` is present in the manifest, detects a spliced, dropped, or swapped item.
3. `revision >= lastSeenRevision` stored locally, detects rollback to an older vault.

**Which identity signs.** The manifest must be signed by the **current active identity**. On an identity rotation (the continuity columns exist but the flow is not wired yet), the manifest is re-signed under the new identity, the same "re-sign on rotation" pattern Bitwarden uses for key rotation. A manifest signed by a non-active identity is rejected, with a future grace path via the continuity cross-signature.

**Can a legitimate user hit a bad signature?** With a correct client, essentially no, a legitimate device always signs with the active identity it holds, so a verification failure means tampering, corruption, or rollback, not normal use. That is why the response is to **refuse and warn**, not to auto-repair. Resolution paths, in order of preference: keep the last-good cached vault and retry (transient/corruption); **cross-check against the public registry** (the keys are independently registered there with their own binding signatures, so a device can confirm which key set is authentic and see exactly what was altered); **restore from the recovery phrase**, which re-derives the VRK and lets the device rebuild and re-sign a fresh manifest from items that verify against the registry.

This mirrors how other systems treat an integrity break as a hard stop with a human decision rather than a silent fix: **Signal** shows a "safety number changed" warning and blocks until acknowledged; **git** flags a bad commit signature and leaves the policy to the caller; **TLS certificate pinning** fails the connection outright; **Apple iCloud Keychain** anchors recovery in HSM attestation so a mismatch cannot be papered over.

### 7.1 How each server mutation is authorized

Two things authorize a request, and they answer different questions: **transport** ("is this really one of the account's devices?") and **payload** ("what does this write mean?").

**Transport auth comes in four tiers**, chosen by whether the caller can hold the identity key at that moment and how sensitive the operation is. The load-bearing idea: the **vault** iframe (which holds the identity key) is loaded whenever a product uses encryption, but the **interface** iframe (which holds the OIDC JWT) is not — so anything that must run silently is authenticated by the **identity signature alone**, not the JWT. "Silently" still means _while the user has a product window open_ (the vault iframe is live in that page); this is not headless, server-side background work. The point is precisely that we can keep the vault synced in that window **without interrupting the user**: we never want to pop a "your session has expired, please sign in again" modal just to push a TOFU decision or pull a remote change. Signing each request with a private key and verifying it against a registered public key, with no bearer token, is the same pattern as SSH, WireGuard, mTLS and WebAuthn.

| Tier                        | Auth required                        | Driven by              | Why                                                                                                                                                                                                             | Endpoints                                                                                                                                             |
| --------------------------- | ------------------------------------ | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Silent / background**     | **Identity signature only** (no JWT) | the vault (autonomous) | must run with no interface and no live JWT; the identity signature proves "an enrolled device of this user", and `userId` travels inside the signed claims so the server targets one identity to verify against | `GET`/`PUT /api/vault/items`, `GET /api/vault/revision`, SSE `/api/vault/events`, `GET /api/emergency-access/pending` (12.7)                          |
| **Interactive + sensitive** | **JWT + identity signature**         | the interface          | the interface is open (JWT is free) and the op is security-relevant, so keep the OIDC-session assurance on top of the key proof                                                                                 | `PUT /api/vault/keyring` (change phrase), device-approval approve / list, emergency designate / wait-time change / re-arm / initiate / recover (12.7) |
| **Cold / no keys yet**      | **JWT (+ passphrase PoP)**           | the interface          | the caller has no identity key yet (restoring / onboarding); the passphrase proof is what gates the `wrappedVRK`                                                                                                | `GET /api/vault/meta`, `POST /api/vault/challenge` `/fetch` `/reactivate` `/vault` (bootstrap), `register/*`                                          |
| **Lost-password**           | **JWT only**                         | the interface          | must work exactly when the user can sign nothing                                                                                                                                                                | `DELETE /api/public-keys`, the emergency fail-safe actions (accept, cancel, reject, delete, lists, search: 12.7)                                      |

**Why keep the JWT _on top of_ the signature for tier 2.** The signature alone is already strong authentication — it is the SSH / WebAuthn key-possession pattern — so tier 2 does not strictly _need_ the JWT for correctness. We keep it because those operations are **rare and sensitive** (changing the recovery phrase, approving a new device), the interface is already open at that moment so the JWT costs nothing, and it is cheap belt-and-suspenders: were there ever a subtle edge in signature verification, the JWT is a second, independent gate that blinds it. It is the same shape as cold-start pairing the JWT with the passphrase proof (there the passphrase does the cryptographic part). For the frequent, silent data-plane we deliberately do not pay that cost, because requiring the JWT is exactly what would force the re-authentication modal we are trying to avoid.

**The `X-Signature` mechanism.** The per-request identity signature (tiers 1 and 2) is a DPoP-style compact JWS (modelled on RFC 9449 / RFC 7515) over `{method, path, body-digest, userId, iat, exp}`, signed by the caller's identity key and sent in an `X-Signature` header (`src/crypto/request-proof.ts`). On the **silent data-plane (tier 1)** it stands alone — no JWT — and the server takes `userId` from the signed `sub`, does one indexed lookup of that user's identity key, and verifies against it (a forged `sub` simply won't verify). On **tier 2** it accompanies the JWT, its `sub` bound to the JWT's user. The **body-digest** (`bh` = base64url SHA-256 of the exact request body, the same idea as AWS SigV4's payload hash and RFC 9421's `Content-Digest`) binds the signature to the payload, so a captured signature cannot be replayed against the same method+path with a **swapped body** — the server hashes the raw bytes it received and rejects any mismatch. A server middleware enforces the whole proof **secure-by-default**: a new vault route is covered automatically and must be _explicitly_ exempted, so the failure mode of forgetting is a rejected legitimate call (loud), never a silently open one. The server verifies the proof against the caller's **active identity** from the registry — so a bare stolen token, lacking the identity key, cannot produce it. Replay is bounded by the covered method+path+body and a short validity window, with **no server-side nonce cache**: the covered reads are idempotent and the covered writes carry their own monotonic-revision replay protection. One deliberate deviation from DPoP: we do not trust a public key embedded in the proof; the server always resolves the key from the registry.

Exempt from the `X-Signature`, and _only_ these, because the caller structurally cannot hold the identity key at that point:

- **cold prerequisites / PoP flows**: `GET /api/vault/meta` (KDF params fetched before any key is derived), `POST /api/vault/challenge` `/fetch` `/reactivate` `/vault` (bootstrap), `register/*`;
- **lost-password disable**: `DELETE /api/public-keys` — it must work precisely when the user can sign nothing, and only ever _disables_ the identity and keyring (never hard-deletes), so a backup reactivates them;
- the emergency-access **fail-safe actions** (accept, cancel, reject, delete, the lists and the contact search): a grantor who lost every device must still be able to refuse a recovery from a bare login, and none of these can ever release key material or shorten a wait (12.7);
- the public directory reads.

The one subtlety is device adoption: a new device must pull `/items` (a covered route) to obtain the very identity key it would sign with. So the enrolled device forwards the **identity secret key alongside the VRK**, both wrapped to the new device's ephemeral key, and the new device signs its own first pull (5.6). No keyless carve-out on `/items`.

**Identity migration and self-auth.** Verifying the `X-Signature` against only the _active_ identity would deadlock a device that is one migration behind (it signs with the old generation the server no longer treats as active, yet it must sync to obtain the new one). The resolution is a walk bounded **two** ways: accept the active identity always; accept a **continuity-linked** predecessor (verifying each cross-signature) only if it is both within a small **hop** bound (N-1…N-3) _and_ within a **time** grace window; otherwise return a distinct "identity too stale / off-chain" error that tells the client to restore from backup. The two bounds do different jobs: the hop bound caps the walk's cost, the **time bound caps cryptographic exposure** — you migrate an identity for a reason (notably retiring a signature key with emerging long-term weakness, the Ed25519 → PQ case this mechanism is reserved for), so an old key must stop authenticating _anything_ once the window closes, not linger usable forever. The time check is **absolute and per-identity, measured against `now`**: a predecessor's "superseded at" is exactly its **successor's `createdAt`** (the successor is minted at the moment the old identity is demoted, so no separate column is needed — the walk already holds the successor), and a predecessor is accepted only while `now − successor.createdAt < WINDOW`. It is emphatically **not** a chained "each migration was within WINDOW of the previous" test — that would let frequent migrations (say every 11 months) walk the chain back many years. With the absolute rule, the oldest key that can authenticate is one retired within the last WINDOW, no matter how often migrations happen. The active identity itself is **never** time-checked (it is accepted unconditionally on the fast path); only superseded predecessors are. The window is set to the **same ~1 year** as the superseded-vault content retention (§9), and the two reinforce each other: past a year the old vault's wrapped VRK + items are purged, so a device still on the old identity would have nothing left to sync anyway. It is deliberately _not_ "any of the user's identities": an **unlinked** older generation (from a start-over or a post-compromise reset) is a trust break and must not authenticate (the walk needs a valid cross-signature to step), and even a linked one expires. This acceptance is **implemented** (`vault.ts`: active key checked first, then `continuityPredecessorWireKeys` walks the chain with the hop + window + cross-signature checks; verified by unit tests including out-of-window, revoked, and forged-link rejection). It is currently **dormant**, not absent: nothing writes continuity links yet (the migration _write_ path is future work, 3.5), so `previousIdentityId` is always null, the walk finds no predecessor, and only the active identity authenticates — but the day migration writes a chain (link + successor `createdAt`, no extra state), the check is already correct and live.

**Payload: content signatures (what a write means).** Independently of transport, any write that changes durable, trust-bearing state carries an Ed25519 signature over a specific canonical object, in the JSON body, verified against a key the server cannot forge:

- vault item writes carry the **manifest signature** (identity over item hashes + monotonic `revision`, Section 7);
- registration and onboarding carry the **binding signature** (identity over `{version, createdAt, keys, userId}`) plus dual proof-of-possession (3.5);
- a rotated identity carries the **continuity signature** by its predecessor (3.4);
- changing the recovery phrase (`PUT /api/vault/keyring`) carries an **auth-binding** signature over the new `authPublicKey`.

Anti-replay/anti-reorder here is the **embedded monotonic counter** the signature covers, not a nonce. This layer is what makes integrity independent of the server; the transport `X-Signature` is defence-in-depth on top of it, and the only thing protecting the covered _reads_ (which have no body to sign).

**Releasing the wrappedVRK (passphrase PoP).** Cold fetch (`/fetch`) and reactivation (`/reactivate`) are gated by a passphrase-derived signature over a **single-use server nonce** (5.3): a read and a state-flip with no meaningful payload to sign, where a server nonce is the simplest anti-replay and matters most for the state change.

**Residual.** With the `X-Signature` in place, a bare stolen JWT (or a rogue server acting within its own API) can no longer even pull the sealed vault — it lacks the identity key. The one mutating endpoint it can still reach is the lost-password **disable**, whose worst case is a **recoverable availability hit** (the owner reactivates from backup). It can never read content, forge a signed item, mint or rotate an identity, or cause irreversible loss — exactly the Section 11 posture (the server is honest-but-curious and possibly compromised for availability; confidentiality and integrity never depend on trusting it).

---

## 8. Failure handling

**Push failure.** Mutations are **write-through and synchronous**: a change is not considered committed until the server confirms it. The choke point computes the new state, pushes it (with the 409 pull-merge-retry loop, all within the one operation), and only then commits to `VaultState` and the local cache; if the push ultimately fails, it raises a **direct, blocking error** and leaves the prior state intact, nothing is silently applied locally and lost. There is deliberately **no cross-session offline write-queue** (a change that could not be saved is simply reported as failed, and the user retries), which keeps the model simple and matches Bitwarden's baseline. The 409 merge-retry loop is not buffering, it resolves a concurrent server-side change inline before the same operation completes.

**Sync triggers (and why SSE is only an optimization).** Background sync runs IN THE VAULT (`src/vault/vault-sync-driver.ts`), authenticated by the identity signature — no interface, no JWT (§7.1, tier 1). It pulls on four occasions: on **start** (a product page opening / the vault loading), on **`visibilitychange`** when the page becomes visible again, on every **(re)connection** of the server-push channel, and on each **server-push wake**. The server-push is an **SSE** stream (`GET /api/vault/events`): a content-free "your vault changed" signal, never any vault data, after which the woken device performs the normal authenticated pull. It carries no security risk (it reveals nothing the server does not already hold — it _is_ the server).

Crucially, **SSE is a latency optimization, not the correctness mechanism**, and the design does not pretend otherwise. A wake can be **missed**: the notifier is an in-memory, per-process registry, so in a **multi-instance** deployment a write handled on one instance does not wake a device connected to another (fix with a shared bus — Postgres `LISTEN/NOTIFY` or Redis pub/sub — or sticky-by-user routing at the gateway); an instance **restart** or a dropped connection also loses in-flight wakes. Convergence therefore does **not** depend on the wake arriving — it depends on the **pull on visibility / open / reconnect**, which fires exactly when it matters: a user is essentially never watching two devices at once expecting instant propagation; the real case is _switching_ to the other device, and that switch makes its page visible, which pulls. This is the same shape Bitwarden uses (SignalR/WebPush for latency, a full authenticated pull as the ground truth).

**Multi-write operations.** Any operation that touches more than one server-side record at once, onboarding (registry + vault + keyring, diagram 5.1) and encryption-key rotation (registry + a new vault item + the manifest), is committed in a **single database transaction** so it is all-or-nothing. This is possible because the registry and the vault share one server and one database. Combined with idempotent writes, a failure or a retry can never leave the server in a half-registered state (for example public keys published without a recoverable backup). This is the same atomic-commit pattern Bitwarden uses for key rotation.

**Integrity failure.** See Section 7 and diagram 5.8, refuse, warn, offer a trusted rebuild path.

**Directory cache staleness.** A product backend that verifies a user's signatures caches their public key using the directory's `ETag` and a short `max-age` (about a minute). For a short window after a key rotation or a reset, that cache can be stale, so a signature made with the new key may be briefly rejected, or a document briefly wrapped for the superseded key. The window is bounded by `max-age` and self-heals on the next revalidation, since the `ETag` changes on rotation and forces a re-fetch. It rarely bites in practice: a user who has just rotated does not immediately return to the product, and by the time they act the caches have revalidated. A backend needing tighter freshness lowers `max-age` or subscribes to the same revision-changed push used for vault sync.

---

## 9. Recovery and lifecycle policy

**Enrollment and recovery, combined.** Device-approval (5.6) is the everyday way to add a device; the mnemonic (5.3) is the recovery fallback for when no other device is available. The mnemonic is shown once at onboarding and printed as the Recovery Kit; after that it is secret and never re-displayed. The QR path forwards the _wrapped VRK_, never the mnemonic, so routine multi-device setup never exposes the long-term secret.

**Recovery Kit wording.** The kit hints that it is needed to restore encrypted data on a new device, without over-explaining exactly what it unlocks. Both **print** (recommended) and **download** are offered. We do not try to "save into a password manager", the item-vs-note ambiguity is not worth it.

**Mnemonic language.** BIP-39 wordlists are language-specific, so the language is a cryptographic parameter, not only UI text: a phrase generated in one wordlist must be entered against that wordlist (the BIP-39 checksum makes a wrong-language entry fail fast). The user is **never asked to pick a language**, it would be an odd, out-of-context question. At generation we **detect it automatically** from the UI/User-Agent locale, falling back to **English** if unsupported, then **store the wordlist language as non-secret metadata (`lang`) in the keyring**. On a new device we **auto-load that stored `lang`** so restore always uses the exact wordlist regardless of that device's locale; the printed Kit states it too. (Auto-detection is fine as the generation-time default precisely because we then persist the real choice, the User-Agent is only a first guess, not what restore relies on.)

**Changing the recovery phrase.** Allowed and cheap (5.7: re-wrap the VRK, no vault re-encryption). The cost is that the **previously printed kit is invalidated**, so we force a re-print with a clear warning. This is the trade-off 1Password avoids by keeping its Secret Key stable forever and letting only the memorized password change, they have two secrets, so the printed one never rotates; we have one by design, so rotating it means re-printing. Bitwarden, which has no printed artifact, simply lets the master password change. Our choice: permit rotation, force re-print, never re-encrypt the vault.

**Recovery model and durability.** Recovery has exactly three routes and no standalone key export: an already-enrolled **device** (its cached VRK), **device-approval** from such a device, and the **recovery phrase** unlocking the server-held vault. There is deliberately **no offline full-private-key export**: it would be a second, more dangerous secret (the blob _is_ the keys, whereas the phrase is useless without the server and a proof-of-possession), and it is redundant with the three routes above. Durability of the server copy is the **operator's** responsibility (database backups/replication), not something offloaded onto every user as a raw-key file, which is where Bitwarden's user-held encrypted export sits and which we intentionally do not adopt.

**Retention and reset.** Losing the phrase with no enrolled device is a **soft de-onboard**, never a destructive delete, so a stolen access token cannot cause permanent loss (see 5.9). The **directory ledger** (identities and encryption-key versions) is **permanent**: it is the audit trail and the source of the monotonic counters, so a reset never resets a version to 1, and a new key is always `ledger max + 1`. Only the **sensitive vault content** (wrapped VRK + sealed items) is purged, after a retention window of one year of `disabledAt`, which also bounds how long private keys sit at rest against a future cryptanalytic break. Within that window the correct phrase **reactivates** the dormant vault; after it, the user does a fresh reset under a new identity and the old encrypted content is lost.

**Starting over never destroys the previous vault.** A user can hold several vaults (keyrings) over time: exactly one is **active** (the current sync target) and any others are **dormant** remnants of superseded vaults. A fresh onboarding mints a new identity and a new vault; if an active vault already exists, its keyring is marked dormant and the new one is created alongside it in the same bootstrap transaction. The dormant vault's wrapped VRK and sealed items are kept intact, so its **own** recovery phrase can still recover it within the retention window. This is what keeps the two flows independent: start over is a brand-new vault, and recovery is a separate phrase-driven path. Trusted-contact escrows (Section 12) follow the same rule: they stay bound to the vault they were created for, so a start-over does not erase them (deliberately: a stolen-session reset must not be able to destroy the user's recovery routes), and they die only when that vault's content is purged at retention expiry, through the credential cascade (12.6).

Recovery is by phrase, and the phrase **self-selects** its vault. The proof of possession verifies against exactly the keyring whose `authPublicKey` the phrase derived, so a fetch returns the one vault that phrase unlocks, active or dormant, without the client ever naming a vault id. The sync and write paths always operate on the active vault, so a single active keyring per user keeps them unambiguous.

When the phrase resolves to a **dormant** vault, the client can bring it back as the current one. Reactivation is a distinct, explicitly confirmed step (it demotes the vault that was active, which stays recoverable by its own phrase), authenticated by the same phrase proof of possession. It is entirely **flag flips**: the recovered keyring is marked active and the previously active one dormant, and the directory is re-pointed at the recovered vault's identity and its latest encryption key, disabling whatever pair was active. Because each keyring records the identity it belongs to, no re-registration is needed. The confirmation matters because there is no separate "disable" gesture: the user is told which vault is being put to sleep, so switching vaults is never silent.

**UI placement.** Onboarding and a "Sync now" + status control are front-and-centre; change-passphrase and the device list live behind an **Advanced** section so the routine experience stays simple and non-alarming.

**Timers.** A short **lock** clears plaintext from memory on inactivity (re-derive instantly from the cached VRK); a long **de-enroll** (~6 months) wipes the device-wrapped VRK so the device must re-enroll, bounding the value of a stolen, still-logged-in device.

---

## 10. Why we model this on password managers

Under the hood, this service and a password manager solve the **same problem**: an **encrypted vault only the user can read, synced across their devices, unlocked by a user secret, with the server never trusted with the contents**. Ours happens to store **encryption keys** — the current one _and_ the rotated history — plus a **trust (TOFU) registry**, rather than logins and notes; but the mechanics are identical (encrypt on the device, store only ciphertext, sync it per-item, recover it from a secret). So instead of inventing a sync-and-recovery scheme from scratch, we borrowed the parts of mature, audited managers that fit our case and deliberately dropped the parts that don't.

**What we borrowed, and from whom:**

- **From Bitwarden — the synchronization model.** A cheap "has anything changed?" check (a revision number), a full pull when it has, and per-item last-write-wins for conflicts. It is simple, well-documented, and independently audited, so a reviewer can map our sync onto a known baseline and only scrutinise where we differ.
- **From 1Password — the high-entropy unlock secret.** 1Password pairs the memorised password with a generated 128-bit "Secret Key" precisely so that a stolen vault can't be guessed offline. We take that idea and go one step further: because the user is **already logged in via the LaSuite's normal sign-in (OIDC)**, our unlock secret is **entirely generated** (the recovery phrase) with no memorised password at all — one strong secret instead of two.

**What we deliberately did _not_ copy:**

- **We don't send a password to log in.** Bitwarden sends a hash of the master password; 1Password uses a zero-knowledge password login (a scheme called SRP). We need neither: LaSuite already authenticates the user, and our secret is randomly generated, so there is nothing password-shaped to protect. We do add a small proof that the caller actually holds the phrase before the server hands back the encrypted vault, but that's a belt-and-suspenders check, not the thing that keeps the data secret — the secret's sheer randomness is what does that.
- **We don't trust the server for integrity.** A plain synced vault trusts the server not to tamper with the stored ciphertext. We instead **sign** the vault with the user's identity key and verify that signature against a key we trust locally plus the independent public registry — so tampering is caught even if the server itself is compromised.

The table is for orientation, not a scorecard — it just shows where our choices land next to two well-known systems:

| Dimension                  | Bitwarden                                 | 1Password                                   | **Our solution**                                                                              |
| -------------------------- | ----------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Unlock secret              | Memorised master password                 | Password **+** generated 128-bit Secret Key | **Generated recovery phrase only** (nothing to memorise)                                      |
| Logging in                 | Password hash sent to server              | Zero-knowledge password login (SRP)         | **LaSuite sign-in (OIDC)** + a small "you hold the phrase" proof before the vault is released |
| Server's view of the vault | Ciphertext (trusted not to tamper)        | Ciphertext (trusted not to tamper)          | **Signed** ciphertext, re-verified against a local key + public registry                      |
| Sync & conflicts           | Per-item, poll-then-pull, last-write-wins | Per-item                                    | **Same as Bitwarden**                                                                         |
| What the vault stores      | Logins, notes                             | Logins, notes                               | **Encryption keys (current + rotated history) + a trust (TOFU) registry**                     |

---

## 11. Threat model summary

The server is assumed **honest-but-curious and potentially compromised** for availability and delivery ordering; confidentiality and integrity must not depend on trusting it.

The table below is a **summary**: one line per threat, one line per defense. The rows carrying a section reference are the ones most easily misread as "gaps", so each is worked through in full underneath, in the same order.

| Threat                                                                                                               | Defense                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Detail       |
| -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| **Stolen OIDC token** downloads the vault                                                                            | The items are under a random VRK, so they are inert without it. The one passphrase-brute-forceable artifact, the `wrappedVRK`, is released only after a proof-of-passphrase, so a bare token cannot even retrieve it.                                                                                                                                                                                                                                                        |              |
| **Server / database leak**, offline brute force                                                                      | The high-entropy recovery phrase is never held by the server (nor the KEK or VRK), so there is nothing to grind.                                                                                                                                                                                                                                                                                                                                                             |              |
| **Server tampering** (splice, reorder, backdate, rollback)                                                           | The signed manifest, verified against a locally-trusted identity and the public registry with a monotonic revision, detects it. Integrity does not rely on the server.                                                                                                                                                                                                                                                                                                       |              |
| **Server substitutes a user's identity** (fake vault to a newly enrolled device, attacker keys returned for a share) | A provisioned device fails closed (5.8), and contacts detect a substituted registry out-of-band (TOFU, 3.4). A substituted share becomes a denial of service against the recipient rather than a read for the attacker, because retrieval is gated by the product's own access model.                                                                                                                                                                                        | §11.1        |
| **Server returns the wrong internal user id** (TOFU is keyed on a server-minted identifier)                          | Barely changes confidentiality: the identifier that keys trust does not decide who the product releases ciphertext to. The internal id is a migration-stability and blast-radius choice, not a confidentiality upgrade over using the sub.                                                                                                                                                                                                                                   | §11.2        |
| **Hostile `oidc_accounts` edit or email-fallback mislink** (attacker's login mapped to a victim's account)           | Trust-critical for authentication, not for E2EE: no VRK, recovery phrase, or identity secret travels with a mislinked login, the vault stays ciphertext behind the proof-of-passphrase, and any identity the attacker registers shows to every contact as a TOFU fingerprint change. Damage profile is a visible identity reset, never silent decryption. Linking needs operator intent or the flagged verified-email fallback (exactly one match, one-year dormancy guard). |              |
| **Compromised device while unlocked**                                                                                | Out of scope, as for every vault product; the de-enroll timer and at-rest device-key wrapping limit the cold-disk case.                                                                                                                                                                                                                                                                                                                                                      |              |
| **Wrong document key / poisoned share**                                                                              | Sharing verifies the recipient's binding signature and the out-of-band-verified fingerprint (TOFU) before wrapping (3.1).                                                                                                                                                                                                                                                                                                                                                    |              |
| **Compromised product swaps recipients** (its share UI displays "Bob <bob@…>" but hands the SDK a different user)    | ACCEPTED residual risk, deliberately not defended: the product already sits inside the plaintext boundary, so lying about recipients adds nothing beyond what the compromise already yields. Still enforced: wrapping is limited to registered directory identities, trust marking is interface-only, and fingerprints are rendered by the interface from vault data.                                                                                                        | §11.3        |
| **Compromised _product_ frontend** (XSS / poisoned dependency in Docs, Drive, …)                                     | The high-water mark of content exposure: it reads what its user decrypts and can enumerate the whole corpus, dormant files included. Iframe isolation still denies it the vault's private keys, trust marking, and raw-key injection. Not defendable by crypto; mitigated operationally (per-product hardening, CSP, dependency pinning).                                                                                                                                    | §11.3        |
| **Compromised vault** (malicious code inside the vault iframe, via a serving-chain or SRI-valid supply-chain breach) | The irreducible trust root, defended in two layers: bundle integrity (isolated origin, build-time SRI, Service Worker pinning) and a `default-src 'none'; connect-src 'self'` CSP that leaves a hash-valid bundle no exfiltration channel on an honest server. Getting data out needs a further serving-chain or backend compromise, and even then stays bounded to in-flight ciphertext plus the keys.                                                                      | §11.4        |
| **Malicious or compromised trusted contact** requests recovery covertly                                              | The waiting period plus escalating out-of-band email notifications: the grantor can refuse from any logged-in session, vault or no vault. Residual risk: a grantor unreachable for the whole wait, bounded by their own choice of wait time and of contact (the feature's premise is a person the user trusts more than they fear losing their data).                                                                                                                        | §12.2        |
| **Trusted contact alone, even holding a revealed emergency phrase**                                                  | Reads nothing: the server serves vault ciphertext only to the grantor's own authenticated OIDC session, and documents live in product backends behind the grantor's OIDC and the products' sharing tables. Recovery discloses a credential, never content.                                                                                                                                                                                                                   | §12.1        |
| **Stolen GRANTOR OIDC session** acts on emergency access                                                             | Can reject, revoke, or start over: all denial, never disclosure. Nothing JWT-reachable can shorten the wait (no early-approve endpoint exists), and a vault reset does not erase escrows. It still cannot read the vault: login does not unlock.                                                                                                                                                                                                                             | §12.2, §12.6 |
| **Stolen CONTACT OIDC session** starts or exercises a recovery                                                       | Cannot even initiate: `initiate` and `recover` require the per-request identity signature (§7.1), produced only by the contact's open vault. With the contact's vault also compromised, the attacker IS the contact for practical purposes, and the grantor-side wait plus notifications still apply.                                                                                                                                                                        | §12.7        |
| **Server releases the capsule or emergency credential early / colludes with the contact**                            | Not cryptographically prevented, exactly as in Bitwarden: the wait period is server policy, enforced twice (hourly job and lazy arithmetic). Stated honestly: once a contact is designated, confidentiality against contact-plus-server collusion is gone by design. The server alone still reads nothing, and a non-colluding contact gains nothing early.                                                                                                                  | §12.3        |
| **Server substitutes the contact's public key at designation time**                                                  | Defeated: designation requires the contact's identity fingerprint to be `trusted` (verified out-of-band) in the grantor's TOFU registry, and the wrap targets the binding-verified key of that pinned identity. The equivalent Bitwarden dialog is skippable; ours is not.                                                                                                                                                                                                   | §12.1        |
| **Server fabricates or alters escrow rows** (fake contact, shortened wait)                                           | The escrow binding signature (grantor identity key) covers the contact, the wait time, the credential's auth-verifier hash and the capsule hash; the grantor's devices audit the list and fail loudly (§5.8 posture), and the server re-verifies it at write. Hiding rows or refusing release remains an availability attack, never a confidentiality one.                                                                                                                   | §12.1        |
| **Contact served a forged escrow record at reveal time**                                                             | The binding signature is verified against the grantor identity **pinned in the contact's own TOFU registry** at verification time, fail-closed.                                                                                                                                                                                                                                                                                                                              | §12.5        |
| **Contact retains the phrase after handover**                                                                        | Burned by construction: the first emergency unlock forces a phrase change whose commit atomically deletes the used credential and re-arms a fresh one (the server rejects the write without the burn). Until then the phrase is a credential the grantor knowingly shares for the handover, and it still reads nothing without the grantor's OIDC session.                                                                                                                   | §12.5        |

### 11.1 A compromised encryption server cannot decrypt, because retrieval is gated by the product, not by us

The encryption server is a blind store: ciphertext, the registry, and routing metadata, never plaintext and never the products' access-control lists. The load-bearing fact is where the per-recipient wrapped keys live: **in the product's own access model, not on the encryption server.** Docs stores them on its `DocumentAccess` rows, keyed by Docs' _local user id_ (not the sub, and not our internal id); the sub is merely the transport identifier the product passes to the SDK, and the vault never holds another recipient's wrapped key. Retrieval is therefore gated by the product's own ACL for its own user, a gate the encryption server has no influence over.

Trace a full server-substitution attack against a share of document `D` whose intended recipient is Bob. The server can lie in either of two ways, and both collapse to the same outcome:

- **(a) right id, wrong key**: it returns Bob's real internal id but the attacker's keys `K-evil`.
- **(b) wrong id, wrong key**: it returns a fresh internal id _and_ `K-evil`.

In both, the vault wraps `D`'s symmetric key for `K-evil`, and the **product** stores that blob on Bob's `DocumentAccess` row (the product chose recipient = Bob; what the encryption service used internally never reached it). Now:

1. **Bob** fetches his row and tries to unwrap with his real key `K-bob`: it **fails**, the blob was wrapped for `K-evil`. Bob loses access.
2. **The attacker** holds `K-evil`'s private key and _could_ decrypt the blob, but cannot **retrieve** it: the product releases Bob's row only to Bob's authenticated session.

So a server acting **alone** turns a substituted share into a **denial of service against Bob, not a read for the attacker**. Delivering the blob to the attacker on top of this requires product-side power (authenticating as Bob, or a product/ACL/DB compromise), at which point we are back in 11.3. The encryption identity and the product's ACL are two independent gates; the server controls only one, which is why the "server substitutes an identity" row is bounded.

### 11.2 Sub-keyed vs internal-id-keyed TOFU barely changes this, and the internal id is just the indirection products already do

Two consequences follow from 11.1.

First, a natural worry: now that TOFU and the registry key on a server-minted internal id, a lying server can return the _wrong_ internal id and we "trust the wrong person". True, but it barely changes the confidentiality outcome, for the same reason: whichever identifier keys the trust store, the wrapped key still lands on the product's `DocumentAccess` row for the recipient the product _intended_, and retrieval stays gated there. The identifier used to key TOFU does not decide who the product releases ciphertext to. A substituted share is still a DoS, not a leak. (This is also why recording the sub on TOFU entries to catch a "known sub, different internal id" swap turns out to add little: it would upgrade a silent DoS into a _detected_ DoS, useful as a signal, but it protects no confidentiality the product ACL was not already protecting. Reasonable to skip unless a product ships a sharing model that does _not_ gate retrieval by the intended recipient, e.g. share-by-link, in which case the wrap-time gate becomes load-bearing again.)

Second, the internal id itself is not exotic: it is exactly the **indirection every product already performs**. Docs maps an OIDC sub to its own local `User` id; Drive to its own; we map it to `users.id`. Each service anchors its data on an identifier it fully owns and converts the sub at its boundary. Ours would be redundant if a single stable identifier existed across the whole suite, but none does, precisely because OIDC subs can change under a provider migration (Section 2.1). The internal id is our stable anchor, playing the same role the product's local user id plays for the product, no more mysterious than that.

So the honest summary: the internal id is not a confidentiality upgrade over using the sub directly (the product ACL carries confidentiality either way). It is a **migration-stability** decision (a stable anchor where the sub cannot be one) and a **blast-radius-placement** one: some component must map a login to a keypair, and the encryption server is the only candidate holding neither plaintext nor an ACL, so anchoring identity there keeps its blast radius bounded by the product's independent gate. The one party you must never make the identity authority is the one holding the plaintext, and no design here does.

### 11.3 A compromised product is out of scope, by construction

The product (Docs, Drive, Meet) hands the cleartext to the SDK at encrypt time and can call `decrypt-with-key` for anything its current user is allowed to read. A malicious or XSS-injected product frontend therefore already reads the plaintext directly and can stream every opened document to an invisible endpoint. No cryptographic measure helps, because the application _is_ the plaintext boundary. This is the universal E2EE property (a backdoored Signal client reads your messages too), not a weakness specific to this design.

This is also **the most damaging** frontend compromise, worse than a compromised vault frontend (11.4), for a reason worth stating: the product can **enumerate**. It sees the user's whole document list and can walk it, decrypting files that have not been opened in months, with their titles and context. A vault compromise only sees ciphertext that someone actively pipes through it. So "product frontend compromised" is the high-water mark of content exposure.

The classic escalation, "the product auto-adds an attacker-controlled recipient to every share so access _persists_ after the compromise is cleaned up", is real but strictly _marginal_: it buys persistence and offline reach, never the initial read, which the product already had. The same reasoning covers the **recipient swap**: a product whose share UI displays "Bob" while handing the SDK a different user is lying about a decision it could already subvert, and its own ACL grant follows the same swapped selection, so the JWT layer is not an independent check here. If that residual is ever judged unacceptable, the lever is to have the **interface** render the recipient confirmation from registry-stored emails (`users.email`, captured from verified IdP claims at login) rather than from product-supplied labels.

What the iframe isolation _does_ buy, and it is not nothing, is that a compromised product frontend cannot read the vault's **private keys** (different origin, unreachable), cannot **mark trust** (accept/refuse are interface-origin-only), and cannot **inject raw keys** (it passes ids; the vault only ever wraps for registered directory identities). So a product-frontend compromise is downgraded from "total key compromise" (the CryptPad/Bitwarden model, where the served app _is_ the vault) to "can exfiltrate what its own user can decrypt, plus add persistence". That downgrade is the point of putting the crypto in an unspoofable iframe.

### 11.4 The vault frontend is the trusted computing base

Everything above assumes the vault's own served code is honest. That code is the **trusted computing base**: the one component that must be correct for every other guarantee in this document to hold. The vault iframe holds the private keys and performs every decryption, so if an attacker runs code of their choosing inside it, the scheme is over, exactly as a backdoored Bitwarden client is over. This is not defended by cryptography; it is defended in two layers, and the distinction between them matters because it decides how much a given compromise can actually do.

**Layer 1, getting malicious code to run at all.** The vault ships from its own isolated origin, every script tag carries a build-time SRI hash, and the Service Worker pins the served bundle. Two attack routes have to be told apart:

- **Serving-chain compromise** (the attacker controls what the server returns): they can rewrite the HTML, its SRI hashes, _and_ the response headers together. This is full control, including Layer 2 below, and is the true "game over". The bar is high (compromise the encryption service's build/serving chain, not one product's frontend).
- **SRI-valid supply-chain compromise** (a poisoned dependency baked into the bundle at build time): the malicious code hash-matches, so it runs, but the HTML and the **HTTP-header-delivered CSP are untouched**, served by an honest server. Layer 2 then still applies to it.

**Layer 2, stopping code that _is_ running from phoning home.** The vault's production CSP is `default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'`. So malicious-but-hash-valid code can decrypt in memory but has **no exfiltration channel to an attacker's own origin**: `connect-src 'self'` blocks `fetch`/XHR/WebSocket to any external host, and `default-src 'none'` blocks the image-beacon and form-post tricks. There are therefore only two ways such code can get data out, and both require a compromise _beyond_ the hash-valid bundle:

- **Loosen the CSP** to permit an external attacker origin. The CSP is an HTTP response header, so this is a serving-chain compromise (the attacker controls what the server returns), not a supply-chain one.
- **Use a same-origin sink.** `connect-src 'self'` still permits requests to the vault's _own_ origin, i.e. the encryption API. So a dedicated attacker-controlled endpoint on that API (or an existing one abused to persist and later reveal the posted bytes) is an exfil sink that needs no CSP change, but it is a **backend** compromise, again beyond the bundle.

So the honest statement is: a hash-valid bundle swap on top of an **honest server (intact CSP header _and_ no cooperating API sink)** has no way to exfiltrate. Impact appears only once the attacker also controls the CSP or an API endpoint. And even then, two things bound and one thing widens the damage:

- **Scope is in-flight only.** The vault sees only ciphertext actively piped through it during the compromise; it cannot enumerate the user's other or dormant documents (no list, no titles), which remains a product-compromise-only capability (11.3). What it _can_ additionally steal is the **private keys**, which lets the attacker decrypt, later and offline, any ciphertext they can separately obtain, still never the immediate corpus.
- **Navigation** is a lesser residual: code could encode data into a URL and navigate the hidden iframe to an attacker host. The neighbouring tricks are already closed: both iframes are embedded with `sandbox="allow-scripts allow-same-origin"` (the minimum the vault needs for IndexedDB and WASM crypto), so no `allow-popups` means `window.open` beaconing fails and no `allow-top-navigation` means it cannot drag the product page away. But **no sandbox token stops a frame from navigating itself**, and CSP has no lever either: the directive designed for it (`navigate-to`) was dropped from the spec and is unsupported by browsers. Containment is therefore Layer 1 plus detection: the exfil is noisy (the parent observes the iframe leaving its origin, breaking the postMessage channel).
- **Crypto sabotage widens it, with no exfil at all.** The deadlier path needs no channel: compromised vault code can weaken randomness or silently add an attacker key as an extra recipient on every wrap, so ciphertext leaks through the **untrusted server/product** it was meant to be protected from. CSP cannot stop this, the tainted output leaves through a legitimate channel. This is why Layer 1 (bundle integrity: SRI + Service Worker pinning) is the load-bearing defense, not Layer 2.

One calibration worth keeping in mind:

- A vault-frontend compromise is, per 11.3, **less** exposing of _content_ than a product-frontend compromise: bounded to in-flight ciphertext, never the enumerable corpus. What it threatens instead is the **keys** and the **integrity of future ciphertext**, which is why its integrity gets the strongest served-code protections in the system.
- The interface frontend (onboarding, settings, verify modal) carries a smaller share of that trust: it drives privileged operations but never holds the long-term keys in a form it can exfiltrate silently, and its sensitive actions require a human present. It is protected by the same SRI/CSP posture, but with a deliberately **wider sandbox** than the vault (`allow-forms allow-downloads allow-popups allow-modals`, needed by the recovery-kit download and the pairing dialogs). So the popup/navigation channels closed above for the vault stay open on the interface host, which is one more reason to keep the long-term secrets on the vault side of the boundary.

---

## 12. Emergency access (trusted contacts)

Every recovery route in Section 9 assumes the user still holds an enrolled device or the printed phrase. Emergency access covers the case where both are gone. The model is Bitwarden's Emergency Access, re-based onto this architecture: the user (the **grantor**) designates a **trusted contact**, an already-onboarded user of this service; designation immediately escrows a dormant recovery route to that contact; if the grantor is ever locked out, the contact requests recovery, and a waiting period the grantor chose (7, 15, or 30 days offered, custom up to 90) starts, during which the grantor can refuse from any logged-in session; if the grantor does nothing, the contact receives an emergency recovery phrase, prints it as a kit, and hands it to the grantor in person.

**Organizational escrow was rejected**: LaSuite is deployed by organizations of very different maturity, so a deployment-held recovery key would, in most deployments, be a standing master key in ordinary IT hands, and it concentrates risk (one compromised escrow key or one coerced admin exposes every user's vault). If a deployment ever needs organization-level recovery, it can be layered on top of this same mechanism (an organization recovery identity acting as a mandatory contact) without changing the model. **M-of-N (Shamir) recovery was set aside** for a different reason: splitting the escrow so that no single contact can recover alone sounds stronger, but it multiplies the coordination and comprehension cost for exactly the users this feature serves, and it multiplies the failure modes (one unreachable share-holder blocks everyone). A single well-chosen contact behind a delay is the right amount of machinery, and because the escrow stores one capsule per contact, shares remain an additive change if a deployment ever truly needs them. Recovery of the OIDC login itself is and stays the identity provider's job; this feature covers only the encryption layer, and the printed kit remains the primary, instant, fully user-controlled route: emergency access is its slow, socially anchored complement. A grantor who has also lost the OIDC account is out of scope by the same split (once they can log in again, the flow applies unchanged), and if the grantor is deceased or incapacitated, the contact ends up holding a passphrase but still reads nothing: the server serves the vault only to the grantor's OIDC session, and documents live in the product backends behind that session and the sharing tables, so actual access additionally requires a product-level or legal process (succession, administrator action on the OIDC account). Emergency access makes such a process meaningful (without the keys, granting ciphertext access yields nothing) but does not replace it. No new cryptographic primitive is introduced anywhere: every operation below composes the existing keyring derivation (4.2), the existing wrap-for-user KEM path (3.1), and the existing length-framed Ed25519 binding-signature pattern (3.5).

### 12.1 The escrow: a dormant emergency passphrase, a second credential of the same vault

What is escrowed is neither the grantor's own phrase (an escrow of it would silently die on every phrase change) nor the raw VRK (the contact would then have to open and rebuild the whole vault on their machine, over-disclosing private keys and the TOFU registry). It is a **fresh, dormant emergency passphrase** for the grantor's own vault, exploiting the credential model of 4.2 LUKS-style: one vault, several keyslots.

At designation, in the grantor's open vault iframe:

```
E          = fresh recovery phrase (32 bytes entropy, 24 BIP-39 words, grantor's wordlist)
credential = the exact keyring derivation of 5.1 run on E:
             KEK_E = Argon2id(E, salt = userId), wrappedVrk = seal(VRK, KEK_E),
             authPublicKey (+ authPubSig by the identity key), kdf params, lang
capsule    = entropy(E) wrapped to the contact's active X-Wing key
             (the standard wrap-for-user wire format of 3.1)
```

The credential mirrors the primary one and unlocks the **same** vault (same VRK, same items), but is stored **dormant**: the unlock proof is never checked against it until the relationship is recovery-approved (12.3). `E` itself is discarded by the vault iframe the moment the credential and capsule are built; it is never stored or displayed anywhere on the grantor's side. The contact's encryption-key **version** used for the wrap is recorded (`granteeKeyVersion`), so the grantor's settings screen can later detect that the capsule targets an outdated key and offer a one-click re-arm (12.6).

What this buys: **the contact never opens the vault.** They only ever end up holding a passphrase, and since the server serves vault ciphertext exclusively to the grantor's own authenticated OIDC session, that passphrase alone reads nothing: no private keys, no documents, no TOFU registry ever reach the contact's machine. Nothing is duplicated either: the grantor keeps their vault, identity, devices, and trust registry untouched, and simply gains one more way in. The handover artifact is a recovery kit, the object users already know.

**Designation is gated on explicit verification.** The vault operation that builds the escrow requires the contact's identity fingerprint to be **`trusted`** in the grantor's TOFU registry: stricter than the share gate of 3.4, where `unknown` passes. Escrowing a way into the whole vault demands a prior out-of-band verification, so `unknown` is rejected. This is precisely what defeats a server that substitutes the contact's key at designation time (the wrap targets the binding-verified key of the pinned, humanly-verified identity).

**The escrow binding signature.** Every escrow is signed by the grantor's identity key over a length-framed canonical payload with the dedicated context `lasuite-encryption/emergency-escrow/v1`, covering: the grantor and contact internal user ids, the pinned contact identity public key, the wait time, the escrow creation time, the SHA-256 of the emergency credential's auth verifier (the verifier itself is never released to any client), and the SHA-256 of the capsule. The server verifies it at write against the grantor's **active** identity (on top of the standard auth-binding check on the credential's verifier, and a check that the pinned identity and wrapped key version are the contact's current ones). It serves three verifiers:

- **the grantor's own devices** audit the `/trusted` list against it in the vault (a row the grantor never created, a swapped contact, an altered wait time, or a substituted credential or capsule fails verification and is surfaced as an integrity warning, §5.8 posture);
- **the contact at reveal time** verifies the record against the grantor identity **pinned in their own TOFU registry**, fail-closed, confirming the escrow really was created by the grantor, for them, with these parameters;
- **the server at write time**, as a coherence gate.

What it does **not** do: prevent the server from releasing the capsule early or hiding rows. The wait period is server policy, exactly as in Bitwarden (12.3, and stated honestly in the Section 11 table).

### 12.2 State machine

```mermaid
%%{init: {'theme':'base','themeVariables':{'fontSize':'15px','primaryColor':'#3b5bdb','primaryTextColor':'#fff','primaryBorderColor':'#2942b8','lineColor':'#5b6ee0','tertiaryColor':'#fff','labelBackgroundColor':'#ffffff','edgeLabelBackground':'#ffffff','transitionColor':'#5b6ee0','transitionLabelColor':'#33406b','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800'},'themeCSS':'.edgeLabel p{background-color:#fff;padding:4px 10px;border-radius:5px;margin:0;} .edgeLabel .labelBkg{background:transparent;} .statediagram-state .nodeLabel p{font-size:15px;padding:5px 12px;margin:0;}','stateDiagram':{'nodeSpacing':70,'rankSpacing':110,'padding':14,'useMaxWidth':true}}}%%
stateDiagram-v2
  direction TB
  [*] --> invited: designation<br/>(grantor builds the escrow, one step)
  invited --> confirmed: accept<br/>(contact, consent only)
  confirmed --> recovery_requested: initiate<br/>(contact, identity-signed)
  recovery_requested --> recovery_approved: waitTimeDays elapsed<br/>(lazy arithmetic)
  recovery_requested --> confirmed: cancel (contact, JWT only)<br/>reject (grantor, JWT only)
  recovery_approved --> confirmed: reject (grantor, JWT only)<br/>credential re-dormant, escrow kept
  recovery_approved --> confirmed: grantor emergency unlock<br/>+ forced phrase change<br/>(credential burned, escrow re-armed)
  note right of confirmed
    delete (either party, JWT only) applies to
    EVERY state: it drops the row and its
    emergency credential, destroying the escrow.
  end note
```

**Designation is one step**, a deliberate divergence from Bitwarden's Invite/Accept/Confirm: contacts are existing, onboarded users found by exact-email search in the local base, so their verified keys exist before designation and the escrow is built immediately. Acceptance is pure consent (no invite tokens, no invitee emails, no second trip by the grantor). Another Bitwarden distinction is collapsed too: their View versus Takeover relationship types make no sense here (this server holds no documents, so a View capability would expose the same key material while reading nothing on its own), leaving a single capability, **recover**.

**There is no early-approve, deliberately.** An approve endpoint could only be authenticated by the grantor's OIDC session: by definition, a grantor who needs recovery has no vault left to sign with. That makes approve exactly as strong as a stolen JWT, and it would let a JWT thief who also suborns the contact collapse the wait to zero. The wait is the entire protection, so **nothing reachable by JWT alone may shorten it**. The cooperative case does not need it: a grantor who still has an enrolled device does not need emergency access at all (any open vault already mints a fresh kit via 5.7), and a grantor with no device waits the delay they themselves chose.

**Reject and cancel stay JWT-only because they fail safe**: the worst a stolen session can do with them is deny a recovery, never obtain one. Reject is allowed even from `recovery_approved` (it re-dormants the credential, killing a revealed-but-unused phrase) and returns the relationship to `confirmed`, escrow kept: a grantor who no longer trusts the contact deletes the relationship instead, which destroys the credential and the row. The wait time is offered as 7/15/30-day presets plus a custom field, server-validated 1 to 90 (with a UI hint that a short wait is risky over long holidays); changing it re-signs the escrow binding (the wait time is inside the signature) and is only allowed outside a running recovery.

### 12.3 The wait period: lazy arithmetic is the authority, the hourly job is for humans

Two mechanisms, deliberately layered:

- **The lazy check is for security.** Every release point (the capsule release in `recover`, and the emergency credential's unlock candidacy in the proof check of 5.3) independently re-computes `recoveryRequestedAt + waitTimeDays <= now()` and treats that arithmetic, not the stored status, as authoritative, flipping the status on the fly if the job missed it. A dead job can silence emails; it can never shorten or lengthen the wait itself.
- **The hourly job runner is for humans.** Under a per-run Postgres advisory lock (so multiple server instances never double-send), it flips overdue requests to `recovery_approved` and emails both parties, sends the escalating reminders below, and purges never-accepted `invited` rows after 90 days.

**Reminder cadence** while a request runs, driven by the time REMAINING until auto-approval and throttled per row: monthly while more than 30 days remain, weekly during the last 30 days, daily during the final 7. This replaces Bitwarden's single final-day reminder, because our waits can span holidays and the grantor's ability to object is the entire security of the scheme. Email is **load-bearing** for the same reason: the notification must reach the grantor outside the app, and refusing requires no vault (reject works from any logged-in OIDC session). The initiate notification is so load-bearing that it is sent before the status flips, and a failed send fails the whole initiate call. Every other step notifies too: designation, acceptance, approval (both parties), rejection, cancellation, revocation, and the completed recovery (both parties). Email links point at an instance-configured product page (`EMAIL_PRODUCT_URL`), with no tokens and no deep routes: after login, the vault fetches the pending actionable state over the silent data plane and the SDK auto-surfaces the right prompt (12.7).

### 12.4 Flows

**Designating a trusted contact (one step).**

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant G as Grantor
  participant UIg as Interface (grantor)
  participant API as Encryption server
  participant UIt as Interface (contact)
  participant T as Trusted contact
  G->>UIg: designate a trusted contact
  UIg->>API: GET /emergency-access/search?email=...
  API-->>UIg: matching ONBOARDED user (or "must onboard first")
  Note over G,T: out-of-band fingerprint verification<br/>(QR or spoken digits, existing verify flow)<br/>MANDATORY unless already trusted
  G->>UIg: choose wait time, designate
  UIg->>UIg: vault op create-emergency-escrow (privileged)
  Note over UIg: require TOFU status trusted<br/>generate emergency phrase E (never stored)<br/>derive dormant credential (wrapped VRK, auth key)<br/>wrap entropy(E) to the contact's X-Wing key<br/>sign the escrow binding (identity key)
  UIg->>API: POST /emergency-access<br/>{credential, capsule, granteeIdentityPub, signature, waitTimeDays}
  Note over API: verify the auth binding + escrow signature<br/>against the grantor's ACTIVE identity<br/>check the pinned identity and key version<br/>are the contact's CURRENT ones<br/>row {status: invited}, credential DORMANT<br/>(the server can read neither)
  API-->>T: email, G designated you as trusted contact
  T->>UIt: open a product, the SDK surfaces the invitation
  UIt->>API: POST /emergency-access/:id/accept (consent only)
  Note over API: status: confirmed
  API-->>G: email, T accepted
```

**Requesting access, refusal or grant, recovery.**

```mermaid
%%{init: {'theme':'base','themeVariables':{'actorBkg':'#3b5bdb','actorTextColor':'#fff','actorBorder':'#2942b8','signalColor':'#5b6ee0','signalTextColor':'#5b6ee0','noteBkgColor':'#ffe08a','noteTextColor':'#1a1a2e','noteBorderColor':'#e0a800','sequenceNumberColor':'#fff'}}}%%
sequenceDiagram
  autonumber
  participant T as Trusted contact
  participant UIt as Interface (contact)
  participant API as Encryption server
  participant UIg as Interface (grantor)
  participant G as Grantor
  T->>UIt: request emergency access (confirmation modal)
  Note over UIt: the request carries the per-request proof<br/>signed with T's IDENTITY key (vault open, 7.1)
  UIt->>API: POST /emergency-access/:id/initiate
  Note over API: verify against T's registered identity<br/>email the grantor FIRST (load-bearing:<br/>a failed send fails the call)<br/>status: recovery_requested
  API-->>G: email, T requested access,<br/>you have N days to refuse
  alt grantor refuses (JWT only, no vault needed, from the email link or the product modal)
    G->>API: POST /emergency-access/:id/reject
    Note over API: back to confirmed, credential re-dormant, escrow kept
    API-->>T: email, request refused
  else grantor says nothing
    Note over API: reminder emails to the grantor: monthly,<br/>then weekly (last 30 days), then daily (last 7)<br/>auto-approve after waitTimeDays<br/>(deadline also re-checked lazily at release)
    Note over API: status: recovery_approved
    API-->>T: email, access granted
    API-->>G: email, access was granted to T
    T->>UIt: reveal the emergency phrase (identity-signed request)
    API-->>UIt: {capsule, escrow record, grantor lang}
    Note over UIt: vault op (privileged), all client-side:<br/>verify the escrow signature against the<br/>PINNED grantor identity (fail-closed)<br/>unwrap the entropy with own private key<br/>render the 24-word phrase, print the kit<br/>repeatable while approved, nothing persisted
    T->>G: hand over the kit (in person)
    G->>UIg: normal cold unlock with E<br/>(the server accepts the now-live credential)
    Note over UIg: forced immediately, before anything else:<br/>set a NEW personal phrase (5.7 flow)
    UIg->>API: atomic write: new primary credential<br/>+ burn the used emergency credential<br/>+ re-arm ALL approved escrows (fresh E', capsule')
    Note over API: status back to confirmed<br/>emails both parties
  end
```

### 12.5 Recovery, then burn + re-arm

While recovery is granted, the server releases to the contact exactly one thing: the capsule, together with the signed escrow record and the grantor's wordlist `lang`. Never items, never keys. The contact's vault verifies the escrow signature against the grantor identity pinned in the contact's own TOFU registry (fail-closed: if the grantor was never verified out-of-band, this is the moment it is enforced), unwraps the entropy with the contact's own key history (newest first, since the history is grow-only), renders the 24-word phrase, and the interface displays it as a printable recovery kit for the handover. The reveal is **repeatable while granted**: a one-time display over a wait of up to 90 days would lose phrases, the grantor may legitimately take weeks to come back, and the phrase is going to be burned anyway. Nothing about the grantor's vault is downloaded, decrypted, or persisted on the contact's side.

The grantor then performs a completely ordinary cold unlock (5.3) with the handed-over phrase on their own OIDC session: the proof simply matches the now-live emergency credential, and the response's `credential_type` flags it. Because the contact has seen this phrase, it is **burned by design**: the interface forces a phrase change before anything else, and that keyring write (5.7) atomically, in one Serializable transaction:

- replaces the primary credential (new personal phrase, new kit),
- deletes the used emergency credential and its capsule (the phrase the contact knows is now dead),
- **re-arms** every relationship that was granted on this vault with a fresh emergency phrase, credential, and capsule (cheap: the vault is open and the contacts are still TOFU-trusted), returning each to `confirmed`,
- and emails both parties once committed.

The server enforces an **exact cover**: the write must carry one re-arm per granted relationship of this vault and nothing extraneous (each re-arm re-verified like a designation), and it is rejected otherwise. A partial rotation could not leave a revealed phrase alive, nor silently strip the user of their recovery contacts. Until the forced change completes, the relationship stays visibly granted and the reminder emails keep nudging the grantor.

### 12.6 Lifecycle

- **Grantor starts over (§5.9): escrows deliberately survive the reset.** They are bound to the (now dormant) vault they were created for and remain exercisable against it: recovering through one lands on the dormant vault and runs the existing reactivation semantics of 5.3. Rationale: an attacker holding only a stolen OIDC session must not be able to erase the user's recovery routes by resetting the vault; with survival, the worst a JWT thief achieves is denial-by-noise, never permanent lockout. The mirror risk (an old trusted contact can resurrect a vault the user deliberately abandoned) is accepted, bounded by the wait, the notifications, and the contacts being verified people, and it is stated plainly in the user documentation. Escrows die only when the vault content is truly purged at retention expiry: purging the vault deletes its credentials (cascade), which deletes the escrow rows (cascade). A new vault starts with zero contacts, and its empty TOFU registry forces re-verification by construction.
- **The contact resets to a new identity** (lost their own vault): the capsule targets private keys that no longer exist anywhere. The grantor's escrow audit detects that the pinned identity is no longer the contact's active one and is not continuity-linked to it, and flags `stale-identity`; renewal is revoke + designate again, which re-runs the mandatory verification.
- **The contact legitimately rotated their identity** (continuity chain): the audit walks the chain exactly as the TOFU check does (3.4) and carries the escrow forward; nothing to do.
- **The contact rotated their encryption key**: nothing breaks (the old private key is still in the contact's grow-only vault), but the recorded `granteeKeyVersion` lags the directory, so the audit flags `outdated-key` and the settings screen offers a **one-click re-arm** (fresh phrase, credential, and capsule replacing the old ones in place, status unchanged).
- **Two contacts recover concurrently**: each relationship has its own independent credential for the same VRK, so two live credentials can coexist; the forced rotation burns and re-arms **every** granted row at once, so no revealed phrase survives it.
- **Phrase revealed but never handed over**: the credential stays live and visible ("access granted"), reminders continue, and the grantor can reject (re-dormant, killing the revealed phrase) or delete at any time from any logged-in session.
- **Designation never accepted**: the row stays `invited`, visible to both sides, revocable by the grantor, and the job runner purges it after 90 days.

### 12.7 How the emergency routes authenticate

The routes reuse the transport-auth tiers of §7.1, mapped by one rule: anything that can release or create key material is signed by the identity key of an open vault, anything that only ever denies is reachable by a bare login.

| Tier (§7.1)                  | Emergency routes                                                                            | Why                                                                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **JWT + identity signature** | designate (`POST`), wait-time change (`PUT`), `rearm`, `initiate`, `recover`                | all performed with an open vault by construction (grantor building an escrow, contact triggering or exercising a recovery), so a stolen OIDC session alone can neither start a recovery nor fetch a capsule |
| **JWT only** (fail-safe)     | `accept`, `cancel`, `reject`, `delete`, the `trusted`/`granted` lists, the contact `search` | a grantor who lost every device must still be able to refuse from a bare login; none of these can release key material or shorten a wait (the worst a stolen session does is deny)                          |
| **Identity signature only**  | `GET /emergency-access/pending`                                                             | fetched by the vault over the silent data plane, so the SDK can auto-surface the pending prompts (a recovery request to refuse, an invitation to accept) on any product page, with no interface and no JWT  |

The designation, re-arm, and burn + re-arm writes run in Serializable transactions (initiate uses a status-guarded update, so concurrent triggers resolve to exactly one running request), and the routes are rate-limited following the repo pattern (10 designations per 24 h per grantor, counted on durable rows; 5 initiates per 24 h per contact and 20 searches per hour, damped per instance). The `search` endpoint necessarily reveals whether an email has an onboarded account; that is accepted inside a collaborative suite (the directory already resolves colleagues), bounded by authentication, exact match only, and the rate limit. An address matching several onboarded users resolves to "nobody designatable" rather than guessing between two humans.

---

## Appendix A: Migrating the OIDC provider (subs change)

A deployment can replace its identity provider mid-life. The new provider mints new `sub` values for the same humans, and nothing in this service breaks cryptographically when that happens: internal ids, signatures, vaults, and TOFU records never reference a sub (Section 2.1). What the migration DOES affect is how logins and directory lookups reconnect to existing accounts.

**The model is a hard cutover, not coexistence.** Exactly one issuer is configured (`OIDC_ISSUER`); switching provider is a configuration change, after which tokens from the old provider are rejected wholesale. Two providers are never accepted simultaneously.

**How each user reconnects.** At a user's first post-cutover login, their token carries an unknown `(issuer, sub)` pair. It is re-attached to their existing account by, in order of preference: an operator-prepared mapping import (when the deployment can export old-sub to new-sub correspondences), or the verified-email fallback (`OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION`), which links when the verified address matches exactly one user who was active within the last year. If neither applies, the login lands on a fresh empty account and the reconciliation gate surfaces the divergence instead of silently splitting the identity.

**The visible symptom during the window.** Directory resolution of subs is scoped to the active issuer, always: a retired-issuer row is never matched, because on a cross-issuer sub collision that could return another person's public key, and a key directory must fail closed rather than guess. Concretely: colleagues of a user who has not yet logged in since the cutover see them as having **no encryption keys** (sharing with them is blocked, visibly), until that user's first post-cutover login re-links their credential. Nothing is lost and nothing heals wrong, it is purely a "this person needs to sign in again" state.

**Runbook implications for operators.**

1. Prepare the sub mapping export from the old provider if it offers one, and import it at cutover; every mapped user then reconnects with zero symptoms.
2. Ensure `OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION` is set consistently with LaSuite products, so a user who continues seamlessly in Docs also continues seamlessly here.
3. Communicate that everyone should sign in again shortly after the switch: each login (in the products AND here) is what refreshes stored subs and re-links credentials.
4. Old `oidc_accounts` rows are never deleted. They stop resolving and stop authenticating, but remain as the audit trail of which provider minted which credential, and as raw material for after-the-fact operator merges.

---

## Appendix B: Email notifications

Transactional email exists in this service almost entirely for **emergency access** (Section 12): the recovery wait period is the grantor's only window to refuse, so a designation, a recovery request, a reminder, or a completion has to reach the grantor out of band. There is no marketing or general-purpose mail, and the rest of the product notifies in-app.

**Rendering.** Emails are built at send time from developer-authored React components (`src/server/email/templates/`) through `@faire/mjml-react` and `mjml`. No user-controlled template is ever compiled: user data (email addresses, day counts, timestamps) enters only as React props, which React escapes when rendering to markup. The output is static HTML plus a plaintext alternative derived from that final HTML with `html-to-text`; no script survives into the message, and links are limited to the instance-configured product URL (no tokens, no deep routes).

**Supply chain.** The MJML toolchain (`mjml`, `@faire/mjml-react`, `html-to-text`, `nodemailer`) is the main added exposure, as with any npm dependency. It is mitigated the same way as the rest of the tree: every version is pinned exactly (no `^`/`~`), so an upgrade is always an explicit, reviewable diff.

**Delivery reliability.** The mailer supports a primary and an optional fallback SMTP transport and retries once before failing loudly, because the emergency-access design depends on the notification actually arriving: a silently lost email would weaken the opposition window. With no SMTP host configured, emails are still rendered (so template errors surface) but only logged, which is the development fallback.
