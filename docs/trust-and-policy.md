# Trust and Policy: Three Reference Designs

> **Status:** working draft. Articulates the trust assumptions and
> authorization policies that the MPC layer below has been
> implicitly relying on, so they can be made explicit before
> Stage 5c implements the policy enforcement.

This document describes the YLDS multi-sig wallet system's trust
model and authorization policies as **three parallel reference
designs**:

- **Current** *(2-of-3, Figure-centric)*: a Figure-centric model
  approximating an ideal with the simplifications the harness has
  today. Figure introduces the IC, runs its own KYC, and gates
  structural changes via its own registry. Good intentions but
  several implicit trust assumptions worth calling out.

- **Owner-key ideal** *(2-of-3 + separate owner key)*: a
  *user-in-charge* model where the wallet holder generates a
  cold-storage **owner key** at wallet creation. The owner key is
  the root of authority for structural changes, separate from the
  MPC share itself. Figure remains a co-signer and issuer-policy
  gatekeeper.

- **Two-share ideal** *(2-of-4, two user shares)*: an alternative
  *user-in-charge* model where the user holds **two MPC shares**
  (`H1`, `H2`) instead of one share + an owner key. The user can
  meet the threshold alone with `{H1, H2}` and is therefore
  unilaterally capable of any structural change — including
  divorcing Figure. F + IC remain available as backup co-signers,
  matching today's lost-share recovery story.

The three are presented side-by-side per use case; gaps between
them, and concrete migration steps, are summarized at the end.

## Foundational principles

These hold across **both** reference designs. They are not
trade-offs to optimize; they are constraints the design has to
satisfy before it is meaningful.

### 1. The IC is an independent party

The Independent Custodian is not "another bb-wrapper process." It
is an organizationally, operationally, legally, and financially
independent entity from Figure. The whole point of an IC is to be
a check on Figure; that check exists only if the IC's
independence is genuine.

Independence has multiple dimensions, all required:

| Dimension | What "independent" means | Counter-example |
|-----------|--------------------------|-----------------|
| **Organizational** | Different legal entity; no parent/subsidiary or controlling-contractor relationship | Figure-owned IC subsidiary |
| **Operational** | Separate operators, infrastructure, ops team | Same engineers running both |
| **Policy** | Independent copy of address policy + TAS pubkeys; ability to refuse Figure | Mirrors Figure without independent check |
| **Legal/jurisdictional** | Figure cannot compel IC via subpoena, court order, internal direction | Same-jurisdiction sister entity |
| **Financial** | Business interests not aligned with Figure | IC depends on Figure for >X% of revenue |

The harness can enforce only the **technical** dimensions
(separate process, separate keys, independent verification
logic). The social/organizational/legal dimensions must be
enforced out of band — by the user's choice of IC, by public
records, by the legal contract that binds the IC.

A consequence: **Figure cannot be the party that introduces the
IC.** If Figure picks the IC, organizational independence is
defeated by construction. The user must select the IC, or
approve it from a pre-vetted pool whose vetting is independent
of Figure. This single point — *who chooses the IC* — turns out
to be the most consequential gap between the current
implementation and any meaningful trust model.

### 2. Independence between F and IC is verified by both, separately

When the system says "F and IC each independently verify a
credential," it means literally that: each runs its own
verification against its own copy of the address policy and TAS
pubkeys, refuses to delegate to the other, and accepts only
verifications it ran itself. The harness's chart structure
already enforces this at the message level (`:event/figure-gate-pass`
and `:event/ic-gate-pass` are separate events that BOTH must
fire). The trust model adds: the *content* IC verifies against
must be independently sourced, not relayed from Figure.

### 3. The user is the principal of their own wallet

Whatever the trust model, the user holds ultimate authority over
structural changes to their own wallet. The two designs differ
on *how* this is realized — separate owner key in one, two
user-held shares in another — but the principle is invariant:
F and IC are intermediaries the user has chosen, and the user
must always have a path to remove them.

A practical consequence: **divorce must always be achievable by
the user without the cooperation of the party being removed.**
If divorcing Figure requires Figure's signature, divorce is a
fiction.

## Cast of trust principals

Beyond the cryptographic actors (H, F, IC) introduced in
`docs/ceremony-message-flows.md`, the trust analysis surfaces
additional principals:

| Principal | What it is | Created by | Held by |
|-----------|-----------|-----------|---------|
| **Holder identity key** | Long-term Ed25519 keypair the bb wrapper holds (Stage 5a/5b.2). Used for capability signing, transport, share-binding proofs. | At process startup | Holder's bb wrapper |
| **Owner key** *(ideal only)* | Separate Ed25519 keypair the user generates **offline** and registers at wallet creation. Authorizes structural changes. Kept somewhere safe (hardware wallet, paper wallet). | User, before keygen | User (cold storage) |
| **Recovery key** | Ed25519 keypair the user pre-commits to at wallet creation. Signs `:crypto/recovery-intent` to authorize lost-share recovery. Kept separately from the holder identity. | User, before keygen | User (cold storage) |
| **Wallet public key** | The MPC wallet's on-chain identity. Preserved across all reshare flavors. | `:ceremony/keygen` | All parties (public) |
| **Address policy** | Per-wallet record describing required attestations, freshness windows, objection-window requirements, registered TAS pubkeys, etc. | At keygen time | F's registry; mirrored at IC |
| **KYC-TAS** | Trusted Attestation Service that authenticates an identity. Issues `:crypto/identity-attestation`. | External service | Independent operator |
| **Commitment-TAS** | TAS that verifies a holder-revealed secret against a previously registered hash. Issues attestation on success. | External service | Independent operator |
| **Social-recovery contacts** | k-of-n contacts pre-designated by the user. Confirm a recovery request out-of-band. | User, at wallet setup | Each contact |
| **Audit log** | Append-only public record of structural events. | F's bb wrapper | F (canonical), IC (mirror) |

The *Owner key* is the principal that distinguishes the
**owner-key ideal** from the current model. The current model
collapses owner-authority into "the user's MPC share + recovery
key" — a meaningful simplification that has consequences this doc
tries to surface. The **two-share ideal** takes a different route:
it dispenses with the owner key entirely and gives the user *two*
MPC shares; the user's threshold-meeting capability with `{H1, H2}`
*is* their owner-authority.

## The two-share design (2-of-4 with H1 + H2)

A natural alternative to the owner-key ideal: instead of giving the
user a separate cold-storage signing key, give the user **two
share-holding identities**, `H1` and `H2`. Configure the wallet as
**2-of-4** with participants `{H1, H2, F, IC}` and threshold `2`.

### Threshold partition

| Subset | Reaches threshold? | Implication |
|--------|--------------------|--------------|
| `{H1, H2}` | Yes (2 of 4) | **User alone can do anything** — sign, refresh, divorce, recover |
| `{F, IC}` | Yes (2 of 4) | F + IC can collude to sign — same fundamental threat as today's 2-of-3 |
| `{H1, F}`, `{H2, IC}`, etc. | Yes | Cooperative pairs — normal day-to-day signing |
| `{H1}` alone, `{H2}` alone, `{F}` alone, `{IC}` alone | No | Single-share loss is recoverable via the others |

The two interesting subsets are `{H1, H2}` (user alone is
sufficient) and `{F, IC}` (the collusion threat, *unchanged from
2-of-3*).

### What the user gains

- **Unilateral routine signing.** No Figure veto over routine
  transactions — the user signs day-to-day with `{H1, H2}` (or
  `{H1, F}` cooperatively if they prefer).
- **Unilateral divorce of anyone.** Holding the threshold alone,
  the user is a sufficient set of "old participants" for any
  reshare. They can drop F entirely (new participants `{H1, H2,
  IC}`), drop IC entirely (`{H1, H2, F}`), or drop both (a
  `{H1, H2}` 2-of-2 wallet) — without that party's cooperation.
- **Graceful recovery for partial loss.** Lose `H1`? The user
  still has `H2`, signs a reshare-recovery with `H2 + F or IC`,
  registers a new `H1'` for the new device. **No KYC + recovery-
  key ceremony needed for single-share loss** — the surviving
  user share is its own authority.
- **Total-loss recovery still works.** Lose both `H1` and `H2`?
  Falls back to today's UC2 flow: `F + IC` produce a new
  shareset under attestation + recovery-intent gate.
- **Cold-key safety via "warm + cold" hybrid.** The user can
  keep `H1` warm (laptop, day-to-day) and `H2` cold (hardware
  wallet, vault). Routine signing uses `H1 + F` cooperatively;
  structural changes pull `H2` out of cold storage to use
  `{H1, H2}` unilaterally. This recovers the cold-key safety
  property of the owner-key ideal while keeping the conceptual
  model simpler (one mechanism — MPC threshold — instead of
  two).

### What does *not* change

- **F + IC collusion** is identical to today. Two of four still
  reaches threshold. The system continues to depend on at least
  one of F or IC being honest (or, equivalently, on F and IC
  being independent so the probability of joint compromise is
  small).
- **The deletion problem persists.** This is the non-obvious
  point — see next subsection.

### The deletion concern (universal across designs)

After any reshare in either ideal model — divorce, recovery,
refresh — F and IC's old share files still sit on their disks.
If both kept their files, they can collude to sign with the
*original* polynomial against the *same* wallet public key
(continuity-preserving reshare doesn't change on-chain identity).
This is true in 2-of-3 today, in the owner-key ideal, and in the
two-share ideal. **No share-rotation operation cryptographically
invalidates old shares; only honest deletion does.**

The misconception note in `docs/ceremony-message-flows.md`
unpacks this in detail. The trust model needs to be explicit:

- **Contractually**, F and IC are required to delete old share
  files on completion of any reshare ceremony. Failure to delete
  is a breach of their contracted custodial role.
- **Audit-attestation-wise**, F and IC each sign a "deleted
  handle `<id>` at time `<T>`" message archived in the audit log.
  This doesn't *prove* deletion (they can lie), but creates an
  artifact that legal liability attaches to.
- **Cryptographically**, the only complete answer is to rotate
  the wallet public key itself — which loses wallet continuity
  (new on-chain identity, attestation policy re-registration,
  prior wallet signatures detached from the rotated wallet).
  Reasonable as an *escape hatch* for users who've truly lost
  trust in F or IC, not as a routine.

The two-share design has one subtle deletion-related upside: the
**operational footprint** of F + IC shares is smaller. With
2-of-4, F and IC's shares are touched only at structural-change
time, not on every routine sign. Less in-memory time means a
smaller forensic-extraction window per share — a defense-in-depth
improvement, even if it doesn't solve the "kept share" problem.

### Pros and cons

| Aspect | Owner-key ideal (2-of-3 + cold owner key) | Two-share ideal (2-of-4, H1+H2) |
|--------|-------------------------------------------|--------------------------------|
| User authority for structural changes | Cold owner key signs requests | User uses `{H1, H2}` to meet threshold |
| User unilateral routine signing | No (still needs Figure cooperation) | **Yes** (using `{H1, H2}` or `{H1, F}`) |
| Onboarding key-generation surface | 3 keys: holder, recovery, owner | 2 share-identities (H1, H2) + recovery key |
| Cold-key safety for structural changes | Yes (owner key cold by default) | Only with the warm-H1 + cold-H2 hybrid |
| Migration cost from current 2-of-3 | Add owner-key registration + signature verification across gates | Add a fourth participant; existing reshare math handles it |
| Wire-format change | Begin-* gain owner-key-signed-request fields | Begin-* gain a fourth peer; participant-id mapping grows |
| Recovery from single user share loss | Use recovery key + KYC TAS gate | Use surviving user share + cooperative co-signer (light) |
| Recovery from total user share loss | Use recovery key + KYC TAS gate (UC2) | Same UC2 path as today |
| Concept count | Three concepts: holder share, recovery key, owner key | Two concepts: user shares (×2), recovery key |
| F + IC collusion threat | Same as today's 2-of-3 | Same as today's 2-of-3 |
| Deletion concern | Same | Same (with smaller F+IC operational footprint) |
| Divorce-of-Figure achievable without Figure | Yes (owner key + IC verifies) | Yes (user has threshold alone) |

The two-share ideal compresses three concepts (holder share +
recovery key + owner key) into two (two user shares + recovery
key) by collapsing "owner authority" into "the wallet's threshold
signing capability with the user's two shares." The
warm-H1 + cold-H2 hybrid recovers cold-key safety as an
operational pattern rather than a structural distinction.

## Reference: real-world deployments (Figure Markets / Cordial Systems)

For grounding, the public architecture of Figure Markets'
Cordial-Treasury-based MPC custody has the following relevant
characteristics (per public Cordial documentation; the
YLDS-context deployment may differ in particulars the user knows
better than public sources):

**MPC protocols.** Cordial Treasury uses different threshold
signing constructions per scheme:
- **ECDSA** — SPDZ with Beaver Triples optimization currently;
  planning to migrate to **dkls23** in the near future.
- **EdDSA** — FROST.
- **Schnorr** — FROST.

This project, by comparison, uses NEAR's `threshold-signatures`
crate (cait-sith-style, OT-based ECDSA on secp256k1). Cordial's
ECDSA path (SPDZ + triples → dkls23) is in the same protocol
family — both are OT-based threshold ECDSA — so the cryptographic
primitives align even though the implementations differ.

**Threshold configurations** they document explicitly:
- `(2, 2)` — both participants must be up; no single point of
  failure but no fault tolerance.
- `(3, 4)` — 1 participant can be down; tolerates one
  unavailability (or compromise) at a time.
- Custom `(t, n)` — flexible per deployment.

Note: the `(2, 3)` configuration this project uses (matching the
holder/Figure/IC trinity) isn't called out by Cordial as a
named example. Their custom `(t, n)` support presumably covers
it, but the user/Figure/IC structure is a named pattern in this
project's design that doesn't have a direct counterpart in the
generic enterprise custody case.

**Policy enforcement is itself MPC**, not just signing. Per
Cordial's docs, every policy decision passes through a Byzantine
agreement across the participating nodes — they use
**CometBFT** as the BFT consensus implementation (the same one
many Cosmos-ecosystem chains use). The property they claim:
*"MPC policy ensures no 'illegal' transaction gets signed due to
a single compromise."* That is, a single compromised participant
cannot unilaterally pass a policy that should fail; the BFT
consensus requires honest-majority agreement across the policy
engines at every node.

This is a stronger property than the *"F and IC each independently
verify, both must pass"* approach our charts describe today. Our
property is effectively a 2-of-2 consensus on policy (both have to
say yes, neither can be overridden). Cordial generalizes this to
BFT consensus with arbitrary thresholds — which is the right
shape if more than two parties run policy engines, but adds
substantial machinery (CometBFT itself is a non-trivial piece of
infrastructure) that the YLDS exploration may or may not want to
adopt at this scale.

**WebAuthn / passkey-based identity** (hardware keys, FaceID,
TPMs) for user authentication on every signed request. This is
close kin to this project's Stage 5a/5b Ed25519 long-term identity
key model — the holder's Ed25519 keypair plays a role analogous
to a WebAuthn credential, and the share-binding proof from
Stage 5a does the analogous job of proving "this credential
controls this share."

**Mapping to this project's roles.** Where the public Cordial
architecture and our exploration overlap naturally:
- "Figure" maps to a Cordial *operating partner* (one of the
  named MPC participants holding a share).
- "IC" maps to a *second operating partner* (or an on-prem node
  owned by the user/institution).
- The holder identity key plays a role analogous to the
  WebAuthn credential.

Where the YLDS recovery use case extends beyond what public
Cordial docs detail:
- The **multi-credential authorization gate** for structural
  ceremonies (KYC TAS + recovery intent, optionally commitment
  reveal + social-recovery contacts).
- The explicit **recovery-intent ceremony** and **objection
  window** for high-value wallets.
- The **IC-as-third-party-operator independence requirement** —
  not just a second node in the MPC consensus, but an
  organizationally / legally / financially distinct entity
  (Foundational Principle #1).

This reference informs design decisions but does not constrain
them. The YLDS context (recovery for tokenized securities, with
explicit attestation policies, structural ceremonies, and the
IC's load-bearing independence) has requirements that go beyond
a generic enterprise custody product.

## Trust matrix (summary)

For each principal, who or what does it trust to do what?

### Owner-key ideal (2-of-3 + separate owner key)

| Principal | Trusts... | ...for |
|-----------|----------|--------|
| User | Owner key, recovery key, KYC-TAS of their choosing, IC of their choosing | Authority to authorize any change to their wallet's state |
| Figure | Owner-key signature on structural-change requests; KYC-TAS pubkey registered in address policy | Authorization for structural ceremonies; identity attestation |
| IC | Same as Figure, evaluated **independently** with its own copy of the address policy | Independent verification; its independence from Figure is the load-bearing trust property |
| KYC-TAS | Its own KYC process | Authentication of identity at attestation time |
| TAS pubkeys in registry | Were registered at keygen by the user | Their continued binding to the right operators |

### Two-share ideal (2-of-4 with H1 + H2)

| Principal | Trusts... | ...for |
|-----------|----------|--------|
| User | Their own H1 + H2 share-identities, KYC-TAS of their choosing, IC of their choosing | Direct threshold-signing capability ⇒ unilateral authority for any wallet operation |
| Figure | A wallet-pk-signed structural-change request (signed by user's `{H1, H2}`); KYC-TAS pubkey registered in address policy (for total-loss recovery) | Authorization for structural ceremonies in the *total-loss* recovery path; otherwise Figure follows the user's direction or refuses based on issuer policy |
| IC | Same as Figure, evaluated **independently** | Independent verification; same load-bearing role as in the owner-key ideal |
| KYC-TAS | Its own KYC process | Authentication of identity at total-loss recovery time |
| TAS pubkeys in registry | Were registered at keygen by the user | Their continued binding to the right operators |

### Current model

| Principal | Trusts... | ...for |
|-----------|----------|--------|
| User | Holder identity key, recovery key, Figure's onboarding process | Routine signing capability via held share; recovery via recovery-intent |
| Figure | Holder identity key (registered at onboarding); recovery key (registered at keygen); its own internally-operated KYC TAS | Authentication during onboarding; authorization for structural changes |
| IC | Address policy mirror Figure provided; same TAS pubkeys Figure registered | Independent verification — but the *content* it verifies against came from Figure |
| KYC-TAS (internal) | Figure's onboarding process | Authentication |

The current model's IC independence is structural (separate
process, separate verification logic) but content-shared (same
TAS pubkeys, same address policy facts). This is closer to "two
audits using the same audit checklist" than "two genuinely
independent audits" — defensible if Figure is honest, weaker if
Figure is the threat.

---

## Use cases

Each use case is presented twice: how it would work in the ideal
model, and how it works in the current implementation. Gaps and
migration notes follow.

### Use case 1 — Onboarding (wallet creation)

**Ideal:**
1. Before approaching Figure, the user provisions an **owner key** (e.g., on a hardware wallet) and a **recovery key** (e.g., printed paper backup).
2. The user obtains a fresh **KYC attestation** from a TAS the user trusts (their bank, an identity provider, etc.) — independent of Figure.
3. The user picks an **IC** from a pre-vetted set (a directory of independent custodians) or supplies one of their own.
4. The user approaches Figure with: owner-pubkey, recovery-pubkey, KYC-attestation, chosen-IC-pubkey, requested address policy.
5. Figure does its own due-diligence (issuer-policy: AML checks, regulatory eligibility) but **does not** authenticate the user's identity — that's already done by the chosen KYC-TAS.
6. Keygen runs. Wallet pubkey + address policy registered. Address policy contains: owner-pubkey, recovery-pubkey, chosen KYC-TAS pubkey, IC pubkey, freshness windows, etc.

**Current:**
1. User approaches Figure for a wallet.
2. Figure runs its own KYC process internally — there is no external KYC-TAS in the harness.
3. Figure introduces an IC of its choosing; user has no role in IC selection.
4. User generates a recovery key during onboarding (or Figure generates one and gives it to the user; design intent is the former).
5. Keygen runs. Address policy is whatever defaults Figure applies.
6. No separate owner key exists; the user's authority is bundled into "the share + the recovery key."

**Violations of foundational principles** *(must be fixed; see
Foundational principles section above):*
- **IC is chosen by Figure.** This violates Foundational
  Principle #1 (IC independence). It is not a "gap to migrate
  from" — it is a structural defect that has to be closed
  before the system can claim independent verification at all.
  The user must choose or approve the IC at keygen, or pick from
  a pool whose vetting is conducted by an entity independent of
  Figure.
- **KYC trust root collapsed.** Figure both onboards the user
  *and* attests to their identity. If Figure is malicious,
  identity attestations are unreliable from day one. The KYC TAS
  must be a separate principal with its own pubkey, registered
  in address policy independently of Figure.

**Other gaps:**
- **No owner key (or only one user-held share).** User has no
  offline-held authority that scales to "any structural change."
- **No external recovery-key registration ceremony.** Recovery
  key registration is implicit in keygen; would benefit from
  being a separate auditable step.

**Migration step:**
- Add `:crypto/owner-key-registration` to the keygen begin payload (optional at first, default to the holder identity key for backwards compat).
- Move the KYC TAS into a separate sibling actor type with its own pubkey registered explicitly in address policy.
- Either user-supplied IC pubkey or pick-from-list at the keygen invocation; in either case, the IC pubkey lands in address policy as a first-class field rather than implicit-from-Figure.

---

### Use case 2 — Routine signing

**Ideal:**
1. Holder constructs a transaction and signs a **sign-request** with the owner key (or holder identity key — see open question below).
2. Figure verifies the owner-key signature on the request, runs its issuer-policy check (AML, daily-limit, etc.).
3. If both pass, Figure participates in the sign ceremony.
4. If Figure refuses (issuer policy says no), the holder can:
   - Try again later, or
   - Initiate a divorce ceremony (with recovery-intent signed by owner key) if they want out of Figure's policy regime.

**Current:**
1. Holder constructs a transaction; the sign-request is currently *not* cryptographically signed by the holder (Stage 4 design — "the cryptographic act of participating in the signing ceremony is the holder's authorization").
2. Figure runs issuer-policy check. Refusal mechanisms are described in the chart but not yet enforced (Stage 5c work).
3. If both proceed, sign ceremony runs.

**Gap:**
- The "holder's MPC participation = authorization" simplification works for routine signing but doesn't scale to *future* signing or *delegated* signing. Once delegation is a thing (e.g., "let alice spend up to X for me"), the request signature matters.
- Figure's veto is unilateral. The holder cannot demand Figure sign. This asymmetry is a design choice; it should be documented as such, not implicit.

**Migration step:**
- Add an explicit holder signature (over the request payload) in `:crypto/sign-request`. Figure verifies it. Initially redundant with MPC participation, but lays the foundation for delegated signing.
- Document the asymmetry (Figure can refuse; holder cannot) with the rationale (issuer regulatory policy is what gives Figure its co-signer role; that role is meaningless without veto power).

---

### Use case 3 — Refresh (periodic share rotation)

**Ideal:**
1. Owner-key signs a **refresh-intent**.
2. Figure verifies the owner-key signature and checks address-policy refresh schedule.
3. IC independently verifies same.
4. Refresh ceremony runs. Each party honestly deletes its old share file (Stage 5c.6+ hygiene work).

**Current:**
1. Refresh is REPL-callable (`orch/refresh`) with no authorization gate.
2. Old share files are NOT deleted by the harness (deletion is operationally separate from the ceremony).

**Gap:**
- **No authorization gate.** Anyone with REPL access to the orchestrator can initiate a refresh. Stage 5c.3 will add the gate; this doc defines what the gate checks.
- **No deletion hygiene.** The misconception note in `docs/ceremony-message-flows.md` already explains this — the rotation benefit only materializes if surviving parties delete.

**Migration step:**
- Refresh authorization gate: owner-key signature on refresh-intent (in ideal model) OR holder-key signature (in current model, where there's no separate owner key).
- A separate (Stage 5c.6) ceremony or hygiene routine that deletes old share files after a refresh ceremony succeeds.

---

### Use case 4 — Voluntary divorce (user removes Figure)

**Ideal:**
1. Owner-key signs a **divorce-intent** specifying which party to remove (almost always Figure) and an optional replacement co-signer.
2. IC verifies the owner-key signature against the registered owner-pubkey and address policy.
3. Figure is not asked. (Figure cannot authorize its own removal.)
4. Reshare runs between holder + IC + (optionally) new-cosigner. New shareset.
5. Figure's share record is retired in the audit log; Figure should also delete its old share file.

**Current:**
1. Divorce is REPL-callable (`orch/divorce`).
2. No authorization gate.
3. Cryptographically, the divorce already works without Figure (run-reshare's protocol-runners = new-participants; Figure is in old-participants but not new, so it isn't contacted).
4. But Figure is required to NOT object — and there's nothing currently stopping Figure from refusing if it had control of the orchestrator (which it does, in production where it plays the coordinator role).

**Gap:**
- **No authorization gate** — same as refresh.
- **Coordinator-role conflict-of-interest.** In production, the coordinator role rotates among parties per ceremony. If Figure is the coordinator at the moment of a divorce-targeting-Figure, it's structurally able to refuse to relay messages. Mitigation: divorce ceremonies should use a coordinator that isn't the removed party. (A small but important policy.)
- **No mechanism today for "user wants out and Figure won't help."** The cryptographic mechanism exists; the orchestration policy does not.

**Migration step:**
- Divorce authorization gate: owner-key (ideal) or holder-key + recovery-key (current) signs divorce-intent. IC alone verifies.
- Coordinator-selection rule: divorce ceremonies use IC as coordinator (not Figure).
- Document explicitly: divorce is the user's escape hatch from Figure's veto in routine signing.

---

### Use case 5 — Lost-share recovery (UC2)

**Ideal:**
1. User contacts their KYC-TAS for a fresh identity attestation (or uses commitment-TAS / social-recovery TAS).
2. User signs a **recovery-intent** with their owner key (held separately from the lost share).
3. F and IC each independently verify (a) the attestation against the registered KYC-TAS pubkey, (b) the recovery-intent against the registered owner-key pubkey, (c) freshness, (d) optionally an objection window has elapsed.
4. Reshare runs. Public key preserved. New_holder's identity is registered.
5. Old share record retired in the bookkeeping. (The cryptographic share material remains valid until F+IC delete — see misconception note.)

**Current:**
1. Recovery is REPL-callable (`orch/reshare` with old/new participant-set difference).
2. No authorization gate executed in code; the gate is described in the chart and walkthrough but not enforced.
3. Recovery-intent signature is conceptually present (chart calls for it) but no signing/verification exists yet.

**Gap:**
- All authorization-gate work is Stage 5c.
- **Recovery-key bootstrap.** In the current model the recovery key is registered at keygen but its issuance/storage path is fuzzy. The user needs a clear "what to do with this and where to store it" handoff at onboarding.
- **TAS heterogeneity.** Real recovery may need to support multiple attestation methods in parallel (KYC + commitment + social, with each address policy specifying which combination is acceptable). The dictionary already accommodates this; the implementation does not.

**Migration step:**
- Implement the authorization gate at F and IC bb wrappers (Stage 5c.3).
- Use stroopwafel-driven Datalog policy evaluation: address policy + verified credentials → `{:authorized? bool}` per side.
- Multi-TAS support: address policy carries an *acceptable-attestation-set* expression (e.g., "KYC alone OR commitment + 1 social contact"); the engine evaluates whether the supplied credentials satisfy.

---

### Use case 6 — Adding/replacing a TAS

**Ideal:**
1. Owner-key signs a TAS-add or TAS-replace request.
2. F and IC each independently verify the owner-key signature.
3. Address policy updated to add/replace the TAS pubkey.

**Current:**
1. Address policy is barely a thing yet; TAS replacement is undefined.

**Gap:** entirely missing. Stage 5c.x.

---

### Use case 7 — Recovery-key rotation

The user's recovery key may need to be rotated (compromised, lost, periodic hygiene).

**Ideal:**
1. Owner-key signs a recovery-key-rotation request including the new recovery-pubkey.
2. F and IC verify owner-key signature.
3. Address policy updated.

**Current:** undefined.

**Gap:** A subtle point — the recovery key is meant for *recovery*, but its rotation needs its own authorization. If the rotation is authorized only by the recovery key itself, then loss of the recovery key means loss of the ability to rotate it (chicken-and-egg). The owner key in the ideal model resolves this: owner authorizes rotations, recovery is a delegated capability.

In the current model without a separate owner key, this becomes a real gap — possibly arguing for adopting the owner-key concept even before full Stage 5c.

---

## Migration map: current → ideal

A suggested ordering of structural moves to evolve from the current
to the ideal model. Each step is independently useful even if the
following ones aren't done.

| # | Move | Why | Cost |
|---|------|-----|------|
| **1** | **User-supplied (or user-approved-from-vetted-pool) IC selection at keygen.** IC pubkey lands in address policy as a first-class field with a clear provenance — *not* a Figure default. | **Closes Foundational Principle #1 violation.** Without this, no other gate enforcement is meaningful, because the IC's independent verification is just Figure-aligned verification dressed up as independent. | Onboarding-flow + UX work; address-policy schema gains an `:ic-pubkey` field; small code |
| **2** | **Separate the KYC TAS into its own actor type with its own pubkey registered in address policy.** Figure cannot self-attest. | Closes the KYC trust-root collapse. Identity attestations stop depending on Figure honesty. | Stage 5c.2 — new actor + simple TAS workflow |
| 3 | Promote `holder identity key` to also serve as a temporary owner key (same key, two roles) | Lays the data path for owner-key signatures without a new key | Small — additional fields in begin-* messages |
| 4 | Add explicit holder-signature on `:crypto/sign-request` | Foundation for delegated signing later | Small — bb-wrapper change |
| 5 | Add address-policy registry as a first-class Figure-side state, mirrored independently at IC | Enables policy-driven gates with independent IC verification | Stage 5c.1 |
| 6 | Implement F's and IC's independent authorization gates using stroopwafel | Realizes the chart's "independent verification" property | Stage 5c.3 — main Stage 5c work |
| 7 | Coordinator-rotation rule: structural ceremonies pick a coordinator that isn't the removed party | Closes the divorce-targeting-coordinator conflict | Small — orchestrator policy |
| 8 | **Choose between owner-key ideal or two-share ideal** for full user-empowerment realization (see below) | Realizes Foundational Principle #3 fully — the user is the principal | Medium; structural — see branches below |

Steps 1 and 2 are foundational principle violations and must come
first; everything else depends on having a genuinely independent
IC and an independent KYC TAS. Steps 3–7 are Stage 5c proper.
Step 8 is the deeper structural shift that captures user
empowerment fully.

### Step 8 branches — owner-key vs two-share

**Branch 8a (owner-key ideal):**
- 8a.1 — Generate cold owner key offline at wallet creation; register pubkey in address policy.
- 8a.2 — Add `:crypto/structural-change-request` signed by owner key; verified at F's and IC's authorization gates.
- 8a.3 — Owner-key UX: cold-storage handoff at onboarding (paper, hardware wallet, etc.).

**Branch 8b (two-share ideal):**
- 8b.1 — Bump configuration to 2-of-4 with `{H1, H2, F, IC}`. Existing reshare math handles 4-party already; smoke runners exercise the new participant set.
- 8b.2 — Onboarding UX: user provisions two devices/identities for `H1` and `H2`. Defaults to warm-`H1` + cold-`H2` for cold-key safety on structural changes.
- 8b.3 — New ceremony: **light-recovery** for single-share loss (lose `H1`, recover via `H2 + F or IC` cooperation, no KYC + recovery-key gate). Distinct from total-loss recovery (UC2) which still uses the full attestation gate.
- 8b.4 — Address-policy schema gains `:user-share-pubkeys [<H1-pk> <H2-pk>]` so F and IC can recognize user-originated requests via "request signed by any registered user share."

The two branches are alternatives, not sequential. Pick one. The
two-share branch (8b) compresses concept count and gives the user
unilateral routine signing as a free side-effect; the owner-key
branch (8a) keeps a 2-of-3 MPC config and adds an authorization
key separate from the wallet's signing capability. Choose based on
which complexity you're more willing to absorb: a 4-party MPC
configuration vs. a separate cold-storage authority key.

Steps 1, 2, 3 are foundation; 4 is the main Stage 5c lift; 5 and 6
are independence work; 7 is the deeper structural change toward the
ideal; 8 is small but important.

---

## Open questions

Things this doc doesn't resolve and that the user should weigh in
on before Stage 5c implementation begins:

1. **Owner-key ideal vs. two-share ideal — pick one (or sequence
   one before the other).** They're the two routes to Foundational
   Principle #3. Two-share collapses three concepts (holder share +
   recovery key + owner key) into two (user shares + recovery key)
   but adds an MPC participant; owner-key keeps 2-of-3 simple but
   adds a separate authority key with cold-storage UX. Either works;
   you cannot have both meaningfully (the owner key would be
   redundant in a 2-of-4 with H1+H2).

2. **In the owner-key branch: should sign-request signatures be
   holder-key or owner-key?** Routine signing happens often (warm
   key); structural changes are rare (cold key). If sign-requests
   need owner-key signatures, the cold key is in play constantly —
   undermining its safety. Likely answer: holder-key signs
   sign-requests; owner-key signs structural-change requests;
   recovery-key signs recovery-intents. Three keys, three purposes.

   *In the two-share branch this question dissolves*: any signed
   action by `{H1, H2}` is by definition the user authorizing it,
   and the warm-`H1` + cold-`H2` hybrid bounds the cold-key
   exposure to structural changes specifically.

3. **What happens when the owner key is lost?** Recovery via
   recovery-key still works (it's a separate key with its own
   purpose). But losing the owner key means losing the ability to
   authorize structural changes other than recovery. Is that
   acceptable? Or should there be an owner-key recovery path
   (e.g., k-of-n social recovery for the owner key itself)?

4. **Independent IC operator — does the harness need to model this,
   or is "the user picks at keygen" enough abstraction?** In the
   harness today the IC is just another bb-wrapper process; in
   production it's run by an independent organization. The design
   should be agnostic, but the harness might benefit from explicit
   IC-as-third-party plumbing.

5. **What does "honest deletion" look like operationally?** The
   misconception note in the message-flows doc explains the
   importance of deletion; the trust model needs to specify when
   it's REQUIRED (e.g., after a divorce or a successful recovery)
   vs RECOMMENDED (after a refresh).

6. **Address-policy mutability.** Once registered, can the address
   policy change? If yes, who authorizes the change? (Likely the
   owner key.) If no, the user is committed to whatever they chose
   at keygen — which is unrealistic for long-lived wallets.

7. **TAS revocation.** What if a TAS is compromised? The address
   policy needs a revocation mechanism, and parties verifying
   against an old TAS attestation need a way to detect revocation.
   Likely a TAS-rotation ceremony plus a revocation list.

8. **Two-share-ideal-specific: how is `H2` provisioned and what
   does a "lost H2" UX look like?** If H2 is on a hardware wallet
   that breaks, the user is back to a 1-share state — recoverable
   via cooperative co-signer, but the user should know the
   procedure. Documentation gap, not a design gap.

9. **Two-share-ideal-specific: do F and IC distinguish requests
   coming from `H1` vs from `H2`?** In the warm-`H1` + cold-`H2`
   hybrid pattern, F or IC seeing a structural-change request
   that was signed by `{H1, H2}` could treat it as
   "high-confidence user authorization" (cold key was in play),
   whereas a routine sign with `{H1, F}` is "warm-only." This
   could feed into per-amount-or-per-action policy gates. Or it
   could be ignored — both shares are user-controlled either way.

10. **Operational deletion enforcement.** Across all three
    designs, the rotation benefit of any reshare depends on F
    and IC honestly deleting old share files. What's the
    contractual / audit / hardware-attested mechanism that makes
    this enforceable in production? Likely a combination of
    contract language, audit attestations signed by F and IC
    after each ceremony, and (eventually) TEE-attested deletion
    proofs. Worth being explicit about in the deployment story
    rather than leaving it implicit.

---

## Where this feeds Stage 5c

Stage 5c implementation should reference this document, with each
sub-stage implementing a specific section's gap:

- **5c.1 — commitment registry**: Use case 1 (onboarding) +
  address-policy-registry first-class status.
- **5c.2 — attestation services**: Use cases 1, 5, 6 — KYC TAS
  becomes a first-class actor type.
- **5c.3 — multi-party authorization gates**: Use cases 3, 4, 5 —
  the gate logic, driven by stroopwafel.
- **5c.4 — objection windows**: Use cases 4, 5 — the
  publish-then-execute timer.
- **5c.5 — end-to-end UC2**: Use case 5 fully working with
  policy gating.

Two structural moves out of band of Stage 5c that this doc surfaces:

- **The owner-key concept** (migration step 7). Whether to
  introduce now or later is a design question the user should
  answer.
- **Coordinator-selection rule for divorce** (migration step 8).
  Small change, big trust-model implication.
