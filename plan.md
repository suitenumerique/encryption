# Signed product operations: working notes

Record of the analysis behind `product-backend-signature.md` (French), which is the document the
team reads to make the call. That one stops after presenting the two options. This one keeps
everything else: the directions that were considered and dropped, the detailed comparison, the
recommendation and its decision criterion, the design of option C, the trust boundary, and the open
questions.

Terminology follows the French document: **A** = change nothing, **B** = one signing key per user
(the identity key, public half resolved from the registry), **C** = one signing key per document,
distributed at share time.

Nothing here is implemented in the product repos.

---

## 1. What comparable products do

| System | Write authorization | Stops a stolen session from destroying encrypted content? |
| --- | --- | --- |
| **Proton Drive / Docs** | Bearer session. Content and keys signed by the user's address key, clients **verify on read** | **No.** Detection, plus trash and versions. The closest peer to us, and it accepts this residual risk |
| **Apple iCloud (Advanced Data Protection)** | Account token, server-enforced ACL | **No.** Mitigated by hardware-bound tokens, 30-day recovery, file versions |
| **Matrix / Element** | Access token; the homeserver signs events for federation, users do not sign their own | **No.** Cross-signing covers device identity, not write authorization |
| **Tresorit** | Cryptographic ACL: membership changes signed by admin keys, clients verify independently of the server | **Partly.** Strong on "who may join"; content writes still ride the session |
| **Signal (Groups v2)** | **Zero-knowledge group credentials**: the server verifies an anonymous proof of membership and role | **Yes**, but storage is append-only, so there is no mutable blob to overwrite |
| **Keybase / KBFS** | Every mutation is a **signed link in a per-team sigchain**, server-verified, append-only, published Merkle root | **Yes**, and tamper-evident, at the cost of a whole sigchain plus Merkle infrastructure |
| **CryptPad** | Per-pad `validateKey` in the channel metadata, the server verifies **every message** and drops invalid ones (`lib/hk-util.js:1049-1080`, `lib/crypto.js`) | **Yes**, exactly our threat, with no identity registry |

Two constants, and neither is "resolve the author's identity key on every request":

1. **Nobody puts a remote identity lookup on the write path.** Where writes are verified, the key is
   attached to the object or already in the verifier's hands.
2. **The check is a capability check, not an identity check.** Keybase is the exception that proves
   the rule, and it pays for it.

CryptPad is the closest working precedent for option C: same threat, no registry, roughly 30 lines
of server code.

---

## 2. Directions considered and dropped

### 2.1 Making the damage reversible (retention policy)

Delay Drive's purge, forbid version deletion on encrypted documents, lengthen restore windows.
**Dropped**: these are retention policies that belong to the products. It is not the encryption
service's place to dictate how long a trash bin lives.

**One carve-out is worth carrying anyway**, because it is not a retention policy but a correctness
fix in our own feature: **never destroy the last wrapped key** when deleting an access row.
`_raise_if_would_strand_pending_users` already exists and covers only the pending-collaborators
case; extending it belongs to the encryption integration. It is also a trap for legitimate users: an
administrator removing the wrong person can make a document undecryptable with no malicious intent.

### 2.2 Rate limiting, anomaly detection, notification

Cap sensitive operations per session, alert on bursts, notify the user. **Dropped as a control**: it
does not hold at scale. A threshold loose enough not to disturb legitimate use leaves an attacker
plenty of room, and notifications drown in noise as the user count grows. It reduces the breadth of
an attack without changing the worst case, so it does not substitute for an authorization decision.

### 2.3 Binding the session to the device

- **Binding the OIDC token** (DPoP, RFC 9449, or mTLS-bound tokens, RFC 8705) requires identity
  provider support. With many suite instances and heterogeneous providers, it cannot be imposed.
- **Binding the session cookie**, via DBSC (Device Bound Session Credentials), requires nothing from
  the identity provider, since the product issues the cookie. Technically the right layer, but DBSC
  is Chrome-only today and still rolling out, needs a server-side implementation in each product,
  and does not cover non-browser API access.
- Above all, **it does nothing against credential theft**: the attacker logs in legitimately and
  gets their own device-bound cookie. Against that scenario, which is the main risk, the only
  effective upstream control is a second factor.

Roadmap item, not a near-term answer, but worth watching: the day device-bound sessions are widely
available, option C becomes defence in depth rather than the primary control.

### 2.4 Step-up confirmation on destructive operations

Require a fresh confirmation for the few irreversible operations, in the style of GitHub's sudo
mode. Since the interface iframe already exists and already holds the vault, that confirmation can
be a real proof of vault access. This is **a narrow version of option C**, applied to a handful of
operations instead of all of them. Keep as a fallback if C is judged too heavy.

---

## 3. Comparison

| | A: do nothing | B: key per user | C: key per document |
| --- | --- | --- | --- |
| Effort | none | high | medium |
| Stops blind overwrite | no | yes | yes |
| Stops mass destruction | no | yes | yes |
| Stops key destruction (French doc §2.3) | no | yes | yes |
| Resists OIDC credential theft (French doc §1.1) | no | **not on its own.** The attacker re-enrols and holds a genuinely valid signing key, so the signature verifies. Protection comes entirely from the product pinning the shared-at version and rejecting unlinked identities, and the failure mode is silent | yes, by construction |
| Depends on the encryption service being up | no | **yes** | no |
| New key lifecycle | no | yes | yes |
| Says which user acted | no | **yes** | no |
| Enforces read-only cryptographically | no | no | **yes** |
| Risk of locking out legitimate users | none | real | real |
| New code in each product | none | registry client, cache, continuity walk, replay cache, permission class | three columns, one verify call, one stamp check |

---

## 4. Recommendation

**If we want prevention, take C rather than B.** C is markedly cheaper, keeps the encryption service
off the products' critical path, and gives cryptographic read-only enforcement for free.

The decisive point is credential theft. Under B, an attacker who resets the identity ends up holding
a **genuinely valid** signing key registered in the victim's name, so their signatures verify and a
backend that simply resolves "this user's active identity" authorizes every destructive operation
they ask for. B therefore does not derive its protection from the signature at all, but from the
product pinning the shared-at key version and rejecting unlinked identities, which is its most
delicate part and fails silently when omitted. Under C the document signing key is wrapped to the
victim's old encryption key, so a freshly re-enrolled attacker cannot open it, and the resistance
needs no product-side policy to be correct. The one thing it gives up, knowing *which* member acted, is not what we are defending
against. If per-user accountability turns out to be required for audit or legal reasons, the fitting
answer is not B but an identity signature **inside** the encrypted payload, verified by readers.

**To carry regardless of the decision**: the carve-out in §2.1, never destroying the last wrapped
key. It closes the only cryptographic-destruction path in the current system, it is a correctness
issue in our own integration, and it also protects against honest mistakes.

**The decision criterion.** C only pays off if the team accepts a real key lifecycle: generation
when encryption is enabled, distribution with the content key, rotation on member removal. Built
halfway, the result is worse than option A, since a signing failure locks legitimate users out of
their own documents while an attacker holding a session still has plenty of unsigned surface.

The serious counter-argument for A stands: our direct peers do not address this problem, and
confidentiality is never at stake.

---

## 5. Design detail for option C

### 5.1 The key covers the document, not just writing

The document key gates **every sensitive operation on that document**, not only content saves:

| Operation | Signed | Why |
| --- | --- | --- |
| Content save (REST snapshot) | yes | the primary destructive one |
| Relay frame (live editing) | yes | same channel, same key (§5.4) |
| Delete, restore, purge, hard-delete | yes | the other destructive one |
| Rename, move | yes | metadata the ACL protects |
| `remove_encryption` | yes | turns the document back to cleartext |
| Add a member | yes | requires wrapping keys anyway, so the vault is already involved |
| Remove a member | yes | plus rotation of both keys |
| Update a member (re-wrap for a rotated encryption key) | yes | a vault operation by construction |
| Delete a version | yes | this is history destruction |
| Create a new document | **no** | no key exists yet, and creation is not destructive |
| Account-level operations | **no** | not document-scoped: that is our API, already covered |

**Composition with roles.** The document key is shared by all editors, so it cannot distinguish an
owner from an editor, and it does not need to. The signature is an **additional** gate, not a
replacement: the backend keeps checking the session identity against the ACL row and its `role`
exactly as today, then also requires the signature. Roles stay in the ACL; the signature only
answers "did the caller hold a document key, or just a cookie". Both must pass.

### 5.2 Format

A detached Ed25519 signature over `sha256(payload) || document_id || operation || stamp`. The
operation name prevents a signature for one action being replayed as another; the document id
prevents cross-document replay. No JWS envelope, and deliberately not RFC 9421: we are signing an
application-level object that must survive a REST call and a WebSocket frame identically, not an
HTTP message. RFC 9421 remains the right standard for signing HTTP messages when intermediaries or
non-browser clients must interoperate; its costs are strict canonicalization that ingress
controllers can silently break, a large implementation surface, and a thin Python ecosystem.

Were B retained instead, the existing proof would first need an **`aud`** claim, without which a
proof minted for one product is replayable at another exposing the same path, plus a distinct
**`typ`** so a proof meant for our API cannot be replayed at a product.

### 5.3 Freshness and ordering: no counter, one stamp

Three distinct questions with different answers:

| Question | Mechanism |
| --- | --- |
| **Freshness**: signed recently? | a timestamp plus a skew window, stateless |
| **Replay**: the same signed request twice? | a nonce cache, or subsumed by ordering |
| **Ordering**: is this state newer than mine? | a monotonic value, or a parent-hash chain |

**Relay frames need only freshness.** Yjs updates are CRDT deltas: applying one twice is a no-op and
out-of-order application converges, so replaying a captured frame achieves nothing by construction.
A monotonic counter would actively hurt, since peers emit concurrently and strict ordering would
reject legitimate frames. That is also the answer to two signatures issued at the same instant: on
the high-frequency channel there is no ordering constraint to violate.

**The REST save is the exception**, because it *replaces* the stored blob rather than merging. An
attacker holding a legitimately signed save from the morning could resubmit it to undo the day, so
this call needs ordering.

**The timestamp can serve as that ordering value**: store the last accepted stamp and require the
new one to be strictly greater and within the skew window. One signed field, no separate counter.
The only snag is clock skew, and the fix is standard: the client does not sign raw wall-clock time,
it signs

```
stamp = max(local_now_ms, last_known_stamp + 1)
```

a **hybrid logical clock**. It behaves as a wall clock in the normal case, so the skew window keeps
its meaning, and as a counter when clocks disagree, so ordering never breaks. The server returns its
stored stamp on rejection and the client retries once.

**Concurrent saves**: one wins, the other gets a conflict. That is optimistic concurrency, exactly
what HTTP `If-Match` does, and it is benign in Docs since each save posts the full Yjs state, which
already contains the peer's changes received through the relay, so the loser's next snapshot is a
superset.

### 5.4 The WebSocket relay

This is one of the places where C is markedly simpler than B. Verifying a relay frame under C is a
plain Ed25519 check against the document's public key, with no user resolution, no registry call and
no session lookup: the relay does not need to know who anyone is, only that the frame was signed by
a key handed to members of that document. Under B the relay would have to resolve a per-user
identity key, which is exactly the kind of remote dependency a relay should not have.

Two levels, and either is defensible:

- **At connection time**, verify a signature on the upgrade request, so a stolen session cannot even
  join the room. Browser constraint: the `WebSocket` API cannot add headers, so the proof travels in
  a query parameter or through the `Sec-WebSocket-Protocol` trick. One signature per connection.
- **Per frame**, tens of microseconds each, which is what CryptPad does at scale. The gain over
  handshake-only is that a session which was legitimate at connect time cannot keep injecting after
  a removal.

**Handshake-only is a perfectly acceptable first step**, and probably the right one to start with:
the durable damage vector is the REST save, which is covered either way, and injected garbage frames
are a nuisance that peers fail to decrypt rather than durable corruption.

### 5.5 Implementation

**In the encryption repo:**

| Change | Files |
| --- | --- |
| Generate the document key pair, wrap and unwrap it alongside the content key | `src/crypto/`, `src/vault/operations/` |
| Product-facing SDK operations (`signDocumentOperation`, wrap/unwrap helpers), non-privileged since products are the callers | `src/vault/message-handler.ts`, `src/shared/constants.ts`, `src/shared/schemas/post-message.ts`, `src/client/` (and the served `client.d.ts`) |
| Document the mechanism and its limit | `architecture.md` §3.3 |

The secret half never crosses the postMessage boundary in the clear: the vault unwraps it, holds it
for the session, and exposes only signing.

**In each product, backend:** three columns (two on the document, one on the access) and the Drive
mirror; one verification helper applied deny-by-default on the §5.1 operations for encrypted
resources; the stamp checks of §5.3; raw-body access before DRF parsing (`request.body` is fine in
Django, and hashing a 5 MB base64 snapshot costs about 10 ms). **Multipart uploads are not covered by
a payload digest**: cover the small JSON call that mints the presigned URL and let S3 authorize the
PUT. The relay (`y-provider`) verifies the handshake, and optionally each frame, against the same
key. No registry client, no cache, no continuity walk.

**In each product, frontend:** Docs has a single `fetchAPI` (`src/api/fetchApi.ts`), already async,
so signing hooks in there. The payload must be **serialized once** and the same string handed to the
signer and to `fetch`, or the digest will not match. That is the classic bug in this kind of
integration and it should be prevented by the shape of the helper, not by discipline.

### 5.6 Configuration: the flag gates the check, not key distribution

**Separate the data model from the gate.** Distributing the document key pair is expensive to add
later; verifying a signature is cheap. A document encrypted before the feature exists has no key
pair, and the server cannot mint one (that would be the substitution attack described in the French
document §4). A member's client can do it lazily on next open, since every member's public
encryption key is in the registry, but that leaves a long tail of documents nobody opens. So:
**always generate and distribute the document key, and let the flag control only whether the
signature is required.**

Following the django-configurations style both products already use:

```python
ENCRYPTION_SIGNATURE_MODE = values.Value(
    "observe", environ_name="ENCRYPTION_SIGNATURE_MODE", environ_prefix=None
)  # off | observe | enforce
ENCRYPTION_SIGNATURE_SKEW_SECONDS = values.PositiveIntegerValue(
    60, environ_name="ENCRYPTION_SIGNATURE_SKEW_SECONDS", environ_prefix=None
)
```

| Mode | Behaviour | Use |
| --- | --- | --- |
| `off` | no verification, no metrics | local development, deployments without encryption |
| `observe` | verify, count, log, **never reject** | rollout phase, and incident kill switch |
| `enforce` | reject on failure | target state |

Default to `observe`, never `off`, so a missing variable degrades to "log without blocking" rather
than "no security and no visibility". Production sets `enforce` explicitly, with an alert if an
instance is found in another mode.

**The kill switch is the strongest argument for the flag.** If clock skew, a client rollout mismatch
or a cached bundle starts rejecting legitimate saves, you want to fall back to `observe` without
shipping. Not hypothetical for Docs, which has a **service worker** (`features/service-worker`): old
bundles linger in browsers and will not sign anything. Hence the deployment order: ship the signing
client, stay in `observe` until the "signature absent" counter drains to zero, which measures how
fast the old bundles age out, then switch to `enforce`.

**Making the mechanism itself a flag** (B or C): the two are not symmetric in cost. C is three
columns and one verify call; B is a registry client, a cache, an `encryption_user_id` mapping, a
continuity walk, a replay cache and a registry-unreachable policy. Shipping both means building
both, which is the cost C avoids. Proportionate answer: keep the **seam** (a `SignatureVerifier`
interface with C as its only implementation), expose the setting with a single valid value so the
configuration surface does not change later, and do not build B until someone asks for
accountability.

**Anticipated objection**: a switch that can disable the check is itself a weakness. Flipping it
requires deploy access, and anyone with deploy access is already a compromised product backend,
which `architecture.md` §11.3 places out of scope. The alert on non-`enforce` production instances
covers the realistic case, which is an operational mistake.

### 5.7 Rollout and tests

1. **Observe**: sign, send, verify, count, never reject. Per-operation counters: absent, invalid,
   valid.
2. **Enforce on encrypted resources**, behind the flag, per product and per environment.
3. Non-encrypted resources stay out of scope: those users may have no vault at all.

Tests per product: forged signature rejected, replayed snapshot rejected, stale stamp rejected,
signature for another document rejected, signature for another operation rejected, reader without a
key rejected on a write, valid operation accepted, and the ACL role check still enforced
independently.

---

## 6. The trust boundary

Under C the products never consult the registry: what they trust is their own database, and
`architecture.md` §11.3 already places a compromised product backend out of scope.

Under B, §3.3 applies: **a product backend that resolves a key from the registry trusts the
registry, and no cryptographic trick removes that.** Cryptography does not bootstrap trust from
nothing. What narrows it:

| Technique | What it removes | What it does not |
| --- | --- | --- |
| **Per-document keys (C)** | The registry from the product path entirely | Anything about a compromised product |
| Pinning the identity in the product database | Silent substitution: a key change becomes a visible event | Makes each product a stale replica of a rotating truth |
| Short-lived registry-signed assertions | Trust in the **network path** and in registry availability | Trust in the registry as the **authority** |
| Continuity chain | Fabricating a legitimate-looking rotation, since forging a link needs the previous private key | Withholding links, whose effect is fail-safe |
| Out-of-band fingerprint | Trust in the registry, for the users who check | Everyone who does not check |
| Transparency log | Undetectable equivocation: an append-only witnessed log catches a registry serving different keys to different verifiers | Prevention. It is detection |

The last row is the answer to "can we be cryptographically certain". The industry answer is **key
transparency**: Certificate Transparency, CONIKS, Google and WhatsApp Key Transparency (deployed
2023), Apple's iMessage Contact Key Verification, Sigstore's Rekor. None makes a directory
trustworthy. They make a lying directory detectable after the fact, turning a silent compromise into
an incident. That is the ceiling, and it applies to everyone.

---

## 7. Open questions

1. **Is prevention worth the lifecycle?** (§4) C only pays off if generation, distribution and
   rotation-on-removal are actually built. Halfway is worse than option A.
2. **Is the §2.1 carve-out carried** (never destroy the last wrapped key)? It closes the only
   cryptographic-destruction path and belongs to our own feature.
3. **What do the backups actually cover?** Bucket versioning enabled, lifecycle retention, Postgres
   PITR window. The severity of the current exposure depends heavily on this, and only the ops team
   can answer.
4. **Does member removal already rotate the content key**, or is it still to build? C's whole
   revocation story rests on it.
5. **Is per-user accountability required anywhere** (audit, legal)? If so, the answer is an identity
   signature inside the content, verified by readers, not B.
6. **Read-only becomes cryptographic** with C. Do we want that now, or is it scope creep? Promoting
   a reader to editor becomes a key delivery.
7. **Relay: per frame, or handshake only?** (§5.4)
8. **Stamp**: agreement on the hybrid logical clock, the skew window value, and which operations get
   the strict monotonic check.
9. **Configuration** (§5.6): the flag gates verification only, key distribution is unconditional. And
   do we keep B as an unimplemented seam, or decide never to build it?
10. **Who owns the verification code?** A shared internal Python package, or a copy per product. A
    copy will drift, and this is security code.
11. **Is a second factor required on the identity provider?** It is the upstream control with the
    most leverage on the worst scenario. It does not change the choice between A and C, but it
    changes the probability of the scenario.
