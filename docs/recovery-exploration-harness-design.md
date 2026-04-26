# YLDS Recovery Exploration Harness: Architecture and Implementation Plan

## Purpose and scope

This document describes an architecture for an **exploration harness**
to develop and validate the YLDS asset-recovery design end-to-end,
starting from the cryptographic primitives verified in the MPC
feasibility spike (`mpc-feasibility-spike.md`) and building outward
toward a working multi-party recovery system.

The harness is explicitly *not* a production system. Its purpose is to
let us run real ceremonies — keygen, sign, reshare with member change
— across separated party processes, with a vocabulary expressive
enough to layer commitment registration and recovery policy on top
once the cryptographic plumbing is solid. The goals are correctness
and inspectability, not throughput, fault tolerance, or operational
hardening.

The architecture is chosen so that the orchestration layer (the part
where design exploration happens) is decoupled from the cryptographic
layer (the part that needs to be precisely correct), and so that
substituting a different cryptographic backend or moving from
simulated to real network transport requires no changes to the
orchestrator. The decoupling is realized through a deliberately
designed EDN message vocabulary and a ceremony-lifecycle statechart,
together forming a stable two-part contract.

## Canonical names

Named entities in this document — actors, cryptographic entities,
wallet state, ceremonies, events — have canonical definitions in
`data-dictionary.edn`. That file is the source of truth for naming
and structural relationships; this document gives prose context and
architectural rationale.

**Two notational forms** are used for the same entities, in different
contexts:

- **Namespaced form** (`:actor/holder`, `:ceremony/sign`,
  `:state/commitment-registry`) is used in `data-dictionary.edn` and
  in the statechart files. The dictionary catalogs heterogeneous
  entity kinds together; namespacing prevents collision and makes it
  obvious which kind is being referenced.

- **Bare form** (`:holder`, `:sign`, `:commitment-registry`) is used
  in EDN message vocabularies, REPL examples, and code, where the
  surrounding context (a `:from` field, a function argument, a
  participant list) makes the entity kind unambiguous. Bare form is
  more readable in examples and on the wire.

The two forms denote the same entities and are interchangeable; the
choice between them is stylistic.

When this document refers to an entity in prose, the dictionary entry
is the unambiguous reference. For example:

- *"the holder"* in prose ↔ `:actor/holder` (dictionary), `:holder` (code)
- *"the Independent Custodian"* / *"the IC"* ↔ `:actor/independent-custodian` / `:ic`
- *"the commitment registry"* ↔ `:state/commitment-registry` / `:commitment-registry`
- *"a recovery reshare ceremony"* ↔ `:ceremony/reshare-recovery` / `:reshare-recovery`
- *"the address policy registry"* ↔ `:state/address-policy-registry` / `:address-policy-registry`

If a concept appears in prose without a dictionary counterpart, that
is a gap to fix in either the prose or the dictionary, not a design
choice.

## High-level shape

Three architectural layers, each with a single responsibility:

```
┌─────────────────────────────────────────────────────────┐
│  Orchestrator                          (pure Clojure)   │
│  - Drives ceremonies from the REPL                      │
│  - Routes EDN protocol messages between parties         │
│  - Holds no cryptographic material                      │
│  - Replaceable per experiment                           │
├─────────────────────────────────────────────────────────┤
│  Per-party harness                  (bb wrapper + Rust) │
│  - Speaks EDN to the outside world                      │
│  - Translates EDN ⟷ JSON over stdio                     │
│  - Holds the party's share material (file-based)        │
│  - Hosts party-specific business logic when it accretes │
├─────────────────────────────────────────────────────────┤
│  Cryptographic core                            (Rust)   │
│  - Pure threshold-signatures driver                     │
│  - JSON in, JSON out, share files on disk               │
│  - Identical binary across all three parties            │
│  - No knowledge of EDN, Figure, commitments, identity   │
└─────────────────────────────────────────────────────────┘
```

The contract between layers is an EDN message vocabulary at the
orchestrator boundary, and a JSON-Lines wire format at the bb-to-Rust
boundary. Both contracts are declarative and stable; implementations
behind them are replaceable.

## The orchestrator

### Why pure Clojure rather than bb at the top

The orchestrator is a long-running interactive harness driven from a
REPL session, not a script. The natural development style is to start
the harness once, then run successive experiments at the REPL —
keygen, inspect, reshare, inspect, sign, verify — each call returning
a value that can be poked at, stored, and reused. bb's startup-speed
advantage is irrelevant when the process is started once and lives all
day; JVM Clojure's library ecosystem (core.async or manifold for
concurrency, all the inspection tooling, the full debugging surface)
materially helps the kind of work the orchestrator does.

Pure Clojure also avoids forcing one-shot semantics on what is
naturally a stateful long-running process. The orchestrator holds the
set of party connections, the routing table, and per-ceremony state
— all of which want to live in atoms or refs that the REPL can poke
at directly.

### What the orchestrator does

In a single sentence: it spawns party processes, routes EDN messages
between them, exposes ceremony functions to the REPL, and enforces
timeouts. Concretely:

The orchestrator manages a pool of party connections. Each connection
is a subprocess (during exploration) or a remote endpoint (when real
transport is added later) speaking EDN over some channel. The
orchestrator does not care which.

For each ceremony, the orchestrator constructs a routing table mapping
party identities to their connections, sends each party a "begin
ceremony" message with appropriate parameters, and then enters a loop
relaying protocol-level messages between parties as they emit them. A
ceremony terminates when every party reports completion (or when the
orchestrator's timeout fires).

The orchestrator never sees share material. When a party finishes
keygen, the orchestrator receives an opaque **handle** — a UUID or
content hash — that the party uses internally as a key into its own
share store. When the orchestrator later says "use handle H for this
sign ceremony," the party loads the corresponding share. The handle
is the only artifact of share material the orchestrator ever touches,
and the orchestrator passes handles between ceremony invocations the
way a TLS library passes session tickets — opaque, signed-by-issuer,
useful only in the right context.

### REPL ergonomics

The shape we want is something like:

```clojure
(def orch (start-orchestrator {:parties {:holder ..., :figure ..., :ic ...}}))

(def k1 (keygen orch [:holder :figure :ic] {:threshold 2}))
;; => {:public-key "0x...", :handles {:holder #uuid "...", :figure ...}}

(def k2 (reshare orch
                 (:handles k1)
                 [:new-holder :figure :ic]
                 {:old-threshold 2 :new-threshold 2}))
;; => {:public-key "0x...", :handles {:new-holder ..., :figure ..., :ic ...}}

(assert (= (:public-key k1) (:public-key k2)))   ; UC2 load-bearing claim

(def sig (sign orch
               (:handles k2)
               {:participants [:new-holder :figure :ic]
                :coordinator :new-holder
                :message <bytes>}))
;; => {:signature ..., :recoverable true}

(verify-signature (:public-key k1) <message> sig)  ; expected true
```

Each ceremony function blocks the REPL thread on a promise; internal
routing concurrency is hidden. This style is impossible to retrofit
onto a script-shaped tool and is the main reason for choosing Clojure
over bb at the orchestrator layer.

## The per-party harness

Each party is a `bb` process plus a `rust` subprocess. The bb wrapper
owns the EDN-facing interface and any party-specific logic; the Rust
subprocess is the cryptographic worker. They communicate over stdio
in JSON Lines.

The reason for the bb layer at every party (rather than orchestrator-
direct-to-Rust) is twofold:

**Format translation.** EDN is the natural lingua franca of a Clojure
environment, but the Rust crate is comfortable with JSON. A bb layer
at each party translates EDN inbound to JSON outbound and vice versa.
Doing this translation in Rust is a moderate amount of `serde`
plumbing for a job that isn't Rust's strength; doing it in bb is two
function calls. The Rust binary stays in a clean JSON-only world.

**Architectural symmetry and a place for business logic.** Once
party-specific business logic arrives — Figure consulting its
commitment registry, the holder doing wallet UX, the IC enforcing
escrow rules — there has to be a layer above the cryptographic core
where that logic lives. Putting bb at every party from the start
means the layer is already there when needed, rather than requiring
restructuring later. The bb wrapper is small enough that having one
even before any business logic exists is not premature; it's setup
for what will follow.

### What the bb wrapper does, today and tomorrow

Today, with no business logic yet:

- Reads EDN from stdin (one form per line, or one form per
  delimited frame).
- Translates control messages (begin ceremony, drop handle, etc.) into
  appropriate spawning of Rust subprocesses.
- Translates protocol-relay messages (encoded as base64-strings inside
  EDN) by passing them straight through to the Rust subprocess as
  JSON-Lines messages on its stdin.
- Reads JSON output from the Rust subprocess and translates it back to
  EDN on its own stdout.
- Stores share files on disk in a per-party directory, indexed by
  handle.

Tomorrow, when business logic accretes:

- Figure-bb consults its commitment registry before allowing a reshare
  ceremony to proceed for a given address. If the commitment-secret
  reveal does not verify, Figure-bb refuses to spawn the Rust reshare
  subprocess and returns an error to the orchestrator.
- Holder-bb (or whatever the holder's local environment is) handles
  the commitment-secret entry UX, possibly storing the commitment
  secret in a more user-friendly way than a raw file.
- IC-bb may have its own escrow rules — e.g., delay-and-publish
  before participating in a reshare, or attestation-of-identity
  requirements.

The point is that the bb layer is the **policy layer** in addition to
being the format-translation layer. The Rust binary is the
**mechanism layer**. The orchestrator is the **experimental harness
layer**.

### Share storage

For exploration, share files live in a per-party directory as
plaintext (e.g., `./holder/shares/<handle>.bin`). This is honest about
the scope: we are validating cryptographic composition, not
production-grade key management. Production deployment would
substitute encryption-at-rest, OS keyring, HSM, or TEE-backed storage,
all of which can be added behind the same bb-wrapper boundary without
changing anything above it.

The handle namespace is per-party. Each party generates its own
handles when it produces a share; the orchestrator collects the per-
party handles from a single ceremony into a map (`{:holder <handle>,
:figure <handle>, ...}`). The orchestrator's view of "the same key"
is this map; no party knows another party's handle.

## The cryptographic core

The Rust binary is the smallest interesting layer. It is essentially
the test from the MPC feasibility spike, restructured as a one-shot
CLI that reads protocol messages from stdin and writes them to
stdout, with the relevant share-file I/O bolted on.

### Lifetime: one-shot per ceremony

Three options were considered:

- **One-shot per ceremony**: the Rust process exists for the duration
  of one keygen / reshare / sign and then exits. Protocol state lives
  on the heap during its lifetime.
- **Long-running daemon**: the Rust process holds protocol state
  across multiple ceremonies; supports concurrent ceremonies if needed.
- **State-checkpointed CLI**: the Rust process serializes its protocol
  state between rounds, allowing a sequence of short-lived invocations
  to drive a single ceremony.

The third option fights the API and gives no benefit; rejected. The
second adds state-management complexity without clear benefit at the
exploration stage. The first is the simplest match to how the
threshold-signatures crate's `Protocol` trait is designed — a state
machine that runs to completion driven by an external message router
— and is the recommended choice.

In one-shot mode, each ceremony invocation is a separate Rust process,
spawned by the bb wrapper with arguments specifying role, ceremony
type, and ceremony-specific parameters. The process reads inbound
messages from stdin, writes outbound messages to stdout, writes its
final result (a share file or a signature) to a designated path, and
exits.

### Wire format: JSON Lines on stdio

JSON Lines (one JSON object per line, separated by newlines) for the
following reasons:

- Trivial to parse from both bb and Rust.
- `tail -f` works for live debugging.
- Hand-craftable for testing and replay.
- Slightly bloated by base64-encoding binary blobs, but byte
  efficiency is not the constraint at exploration scale.

The JSON message vocabulary has the same shape as the EDN vocabulary
(see appendix), with binary protocol bodies encoded as base64 strings.
The bb wrapper does the base64-and-shape translation in both
directions.

## Party symmetry and role asymmetry

The three parties — holder, Figure, and the Independent Custodian (IC)
— sit in a layered relationship
to each other that is worth being explicit about, because the harness
deliberately exploits one layer's symmetry to simplify early stages,
and that simplification hides asymmetries that are load-bearing for
the production design.

### At the cryptographic layer, the parties are interchangeable

The threshold-signatures crate makes no distinction between parties.
They are identified only by integer identifiers (party 0, party 1,
party 2 in our test); the protocol does not know which is the holder,
which is Figure, which is the IC. Each runs identical code, holds a
share of mathematically equivalent structure, and contributes equally
to keygen, reshare, and sign. Replacing one party with another at this
layer is a relabeling, not a structural change.

This is the symmetry the MPC feasibility spike validated, and it is a
property of how multi-party computation works in general: the math is
blind to who is running each instance.

### At the trust and business-logic layer, the parties are deliberately distinct

The reason there are three parties at all is to spread trust across
distinct domains. A 2-of-3 threshold scheme controlled by a single
entity provides no meaningful security advantage over that entity
holding the key directly; the security argument depends entirely on
the three parties being controlled by different organizations, with
different incentives, different attack surfaces, and ideally different
jurisdictions.

This means substitution at the trust layer is *not* free even though
the math permits it: replacing the IC with another instance of Figure
collapses the threat model even though every cryptographic operation
continues to work. The harness can treat the three parties as
interchangeable for testing cryptographic composition; the real system
cannot.

In addition, each party will accrete role-specific business logic that
does not exist at the others:

- **Figure** is the registry-keeper. Figure maintains the commitment
  registry, the address-to-commitment mapping, the objection-window
  state machine, and the policy decisions about whether a recovery is
  authorized for a given address. None of this exists at the holder
  or the IC. Figure's role is shaped by being the issuer of YLDS
  (and other tokenized assets) and the natural anchor for
  issuer-controlled recovery policy.

- **The holder** is the end user. Holder-side logic is wallet UX —
  how a commitment secret is generated, where and how it is stored,
  how it is presented at recovery time, possibly how it is
  distributed across recovery contacts in a social-recovery scheme.
  Figure and the IC have no UX concerns; they are services, not
  user-facing software.

- **The IC** is the independent custodian. The IC's role is structurally
  different from Figure's even before any business logic is added: the
  IC is held in *reserve*, online only for ceremonies that change the
  wallet's structure (recovery, divorce, refresh) and absent during
  routine signing. This operational profile is described in the next
  subsection. IC-side logic, when it accretes, is whatever assurances
  the IC provides: attestation of identity, escrow rules,
  delay-and-publish before participating in a reshare, possibly an
  independently mirrored copy of the commitment registry to cross-check
  against Figure's. The IC exists precisely to do things Figure does
  not do; if the IC and Figure ran identical software with identical
  state, the IC would add nothing to the trust model.

In the exploration harness as scoped through Stage 4, none of this
business-logic asymmetry is present. All three parties are pure
cryptographic workers running identical bb+rust combos with different
role flags, and the symmetry claim holds literally at the
business-logic layer. The asymmetry surfaces at Stage 5, when business
logic begins to accrete at each party. This is the point at which
"any actor is interchangeable" stops being true even at the
implementation level: the three party-bb wrappers will host
substantively different logic, in different programs, possibly in
different runtimes.

### At the operational layer, the IC is held in reserve

Beyond the trust-and-business-logic asymmetry, there is a third axis
of asymmetry that is load-bearing for the production design: the IC
is **operationally absent during routine signing**. Routine signing is
performed by holder + Figure as a 2-of-3 threshold subset, with the IC
offline. The IC comes online only for ceremonies that change the
wallet's cryptographic structure — recovery, divorce, refresh.

This is not a degradation of the threshold scheme; it is exactly what
threshold signatures permit. In a 2-of-3 scheme, any 2 parties can
produce a signature; the third does not need to participate, does not
need to know the signing happened, and does not need to be online.
The IC's share is held offline, in colder storage than Figure's, with
different operational characteristics matched to its purpose.

The reasons this matters:

- **Operational fragility.** If the IC had to be online for every
  signing operation, IC downtime would be wallet downtime. A service
  whose entire purpose is to be a *backup* trust domain becomes
  paradoxically a single point of failure for routine signing. The
  reserved-custodian model eliminates this.

- **Attack surface.** A party with a long-lived online MPC share
  participating in every signing operation is a high-value,
  always-reachable target. A party whose share is offline 99.9% of the
  time and only comes online for rare structural ceremonies is a much
  smaller attack surface.

- **Cost-benefit alignment.** The IC adds value during rare events
  (recovery, divorce) but would do operational work for every
  transaction if it were on the routine-signing path. The
  reserved-custodian model aligns the operational profile with the
  value profile: the IC works rarely, and only when it adds value.

The cryptographic protocol that supports this model is OT-based ECDSA
(the variant in `threshold-signatures::ecdsa::ot_based_ecdsa`), not
robust ECDSA. Both schemes implement the same threshold-ECDSA
primitive on secp256k1 with equivalent security properties, but
robust ECDSA imposes a presign-time participant-count constraint
(`n ≥ 2t-1`) that prevents the IC from being absent during routine
signing in a 2-of-3 scheme. OT-based ECDSA has no such constraint:
any subset of size ≥ t can complete the full pipeline (triple
generation, presign, sign) with no involvement from the others. This
is empirically verified by the `ot_offline_custodian` test in the
MPC feasibility spike.

A consequence of this asymmetry: the IC's role in the harness is
also different from Figure's. The IC participates in keygen at wallet
creation, then is dormant until a structural ceremony is initiated.
Routine signing ceremonies do not involve the IC at all. This is
reflected in the EDN vocabulary as the IC simply not being in the
participant list for routine sign ceremonies, and in the ceremony
statechart as the IC having no per-party substate during routine
signing.

The implementation plan reflects this in Stages 4 and 5: Stage 4's
"signing ceremony" tests use the 2-party {holder, Figure} subset,
not the full 3-party set. Stage 5's structural ceremonies (recovery,
divorce, refresh) bring the IC online for the duration of the
ceremony.

### The orchestrator is a fourth role, harness-specific

The orchestrator does not have a direct counterpart in the production
system. In the harness it is a distinct fourth actor: not a party,
not a trust domain, but the experimental scaffold that drives
ceremonies and routes messages between the three real actors. It has
authority the parties do not — it can cancel ceremonies, enforce
timeouts, decide what counts as ceremony success. This authority is
appropriate for an experimental harness driven from a REPL, but does
not generalize.

In a production deployment, the orchestrator's responsibilities
distribute across the parties. Typically one party serves as the
**ceremony coordinator** for any given operation — usually Figure for
issuer-policy operations like recovery, possibly the holder for
routine signing operations the holder initiates, possibly rotating
across parties depending on ceremony type. The coordinator party
plays the role the orchestrator plays in the harness, but without the
central authority: in production, every party is a peer, and the
"coordinator" is a transient role bestowed by ceremony context.

This is a real architectural transition, not just a transport
substitution. Moving from harness to production means:

- Spreading orchestration logic from a single Clojure namespace into
  the three party-bbs, each of which gains the ability to drive
  ceremonies it initiates.
- Replacing the orchestrator's central message routing with
  peer-to-peer message exchange, with the coordinator party serving
  as the rendezvous point for protocol messages.
- Replacing REPL-driven ceremony invocation with whatever production
  trigger is appropriate (HTTP API call, scheduled job, on-chain
  event, user action in a wallet UI).

The EDN interface and ceremony statechart survive this transition
unchanged: the messages exchanged remain the same, and the lifecycle
a ceremony goes through is structurally the same regardless of
whether the lifecycle is being driven by a central orchestrator or by
a coordinator party. That is the payoff of the contract-first
architecture — the contract was designed to span both contexts, and
the implementation behind it can be restructured without breaking it.

### How to read the rest of this document

When the document discusses "the three parties" as if they were
interchangeable, the claim is true at the cryptographic and Stage 1–4
implementation layers. When the document discusses Figure-side or
holder-side or IC-side concerns specifically, those are Stage 5
concerns and reflect the trust-and-business-logic asymmetry that this
section establishes.

When the document discusses routine signing involving only holder +
Figure, that reflects the operational asymmetry: the IC is offline
during routine signing and online only for structural ceremonies. The
cryptographic protocol that supports this model is OT-based ECDSA, and
this is the production protocol for the YLDS recovery system.

When the document discusses "the orchestrator," that is the
harness-only fourth role. The production analog is "the ceremony
coordinator," which is a transient role one of the three parties
plays for the duration of a single ceremony, not a separate piece of
software.

## The EDN interface vocabulary

The EDN vocabulary between orchestrator and party is the contract that
makes everything else replaceable. It is small enough to write down in
full in this document (see appendix), and it should be designed
deliberately rather than emerge accidentally.

The vocabulary breaks naturally into three categories:

**Lifecycle / control messages** — orchestrator → party. "Start a
keygen ceremony with id X, you are party Y, threshold T, peers are Z.
Use handle H for your old share if relevant. Use the public key P as
the continuity anchor if this is a reshare." Each is a single EDN map.

**Protocol relay messages** — bidirectional, carry opaque
cryptographic content. "From party A, here is a blob (base64) intended
for party B" or "From party A, here is a blob intended for everyone."
The orchestrator routes these without ever interpreting the blob.

**Result and event messages** — party → orchestrator. "Ceremony X
complete; my new share is registered as handle H; the public key
is P." "Ceremony X aborted because of error E." Optional heartbeat or
progress messages can be added if useful.

Roughly a dozen total message shapes. Manageable, hand-writable,
hand-validatable, and finite.

## Ceremony lifecycle as a statechart

The EDN vocabulary defines the *events* that flow between orchestrator
and parties. A statechart defines the *states* those events transition
between — and, equally importantly, the states they *don't*. The two
artifacts are complementary halves of the orchestrator's contract:
the vocabulary names the events; the statechart says when each event
is legal, what it does, and what state the system ends up in.

### Why a statechart specifically

Multi-party ceremony orchestration is a stateful coordination problem
of exactly the shape Harel statecharts were invented for. A ceremony
has a hierarchical lifecycle (the ceremony as a whole, with parallel
per-party sub-states), it is event-driven (party messages, timeouts,
cancels), and it is rich in failure modes that all need to be handled
correctly. Procedural code for this kind of orchestration reliably
ends up as a tangle of conditionals that misses cases the first time
through. A statechart forces enumeration of the cases up front, makes
the invariants explicit, and gives you a single artifact that can be
visualized and reviewed independently of execution.

The discriminator: any time the natural way to describe a piece of
behavior involves the word "and also if X happens during Y," that's
a sign the procedural form is inadequate and the statechart form is
better. Ceremony orchestration is densely populated with this kind of
description.

### Where statecharts earn their keep, and where they don't

**Strong fit: the orchestrator's per-ceremony lifecycle.** This is
the place where the statechart pays for itself. Each ceremony runs
through a small but non-trivial set of high-level states (pending,
starting, running, finalizing, complete, aborting, failed), and
within `running` there is a parallel region with one sub-state per
party (awaiting-output, relaying, done, errored, timeout). Failure
transitions out of `running` are where the value lives: any party
errored → aborting; cancel received → aborting; deadline elapsed →
aborting with reason `:timeout`; all parties done → finalizing.
Writing these as guarded transitions reads as the actual control
flow; writing them as procedural code reads as accidental complexity.

**Not a fit: the cryptographic protocol itself.** The
threshold-signatures crate is already a state machine — that is
literally what its `Protocol` trait is. Modeling that layer
externally would be redundant and risk drift between the model and
the implementation. The statechart's responsibility ends at the
boundary of the EDN interface; what happens inside the Rust binary
is opaque to the chart by design.

**Probably not a fit yet: per-party-bb behavior.** During the
exploration stages, the party-bb's job is procedural enough that a
statechart adds more structure than it earns: receive a begin
message, spawn the Rust subprocess, route messages between stdio and
EDN, report completion. The implicit state machine has only three or
four states and few transitions. This calculus changes once business
logic accretes at the party-bbs (the Stage 5 work below — Figure
consulting commitment registries, the holder doing UX, the IC
enforcing escrow rules). At that point a `commitment-gated-reshare`
participation flow becomes substantively stateful (request received
→ commitment looked up → reveal verified → objection window
elapsed → participate or abort) and earns its own statechart. That is
work for later; the orchestrator-side chart is the one that earns its
keep from day one.

### Statechart as specification, not just runtime structure

A useful framing: the statechart is the *specification* for ceremony
behavior, and the running code is one possible *implementation* of
that specification. Whether the orchestrator literally executes the
statechart (e.g., via clj-statecharts) or merely conforms to it is a
secondary question. Either way the chart is the source of truth, and
the code can be reviewed for conformance against it.

This separation matters because:

- The statechart can be reviewed and discussed by people who do not
  write Clojure — security reviewers, regulators, integrators, future
  collaborators. A visual lifecycle diagram is a far more accessible
  artifact than a Clojure namespace.
- The statechart can be changed in advance of code, with the change
  reviewable as a pure-design artifact before any implementation.
  This is unusually valuable for orchestration logic, where the cost
  of getting transitions wrong is high.
- The statechart can be tested independently of the implementation
  — assertions like "every state has a handler for `:cancel`" or
  "no path from `:complete` returns to `:running`" are checkable as
  properties of the chart itself, separate from any code.
- If the statechart is *also* executed at runtime (the strongest
  form), conformance is automatic: the running code cannot diverge
  from the spec, because the spec is the running code. This is the
  ideal endpoint, but the documentation-only form is already a large
  fraction of the value.

### Choice of statechart library

The orchestrator runs in a JVM Clojure environment, so any
statechart library used at runtime must support that target. The
upstream `clj-statecharts` library by lucywang000 runs on the JVM;
a fork at `franks42/clj-statecharts-bb-scittle` extends it to run on
Babashka and Scittle (worth verifying that JVM compatibility is
preserved in the fork). For the exploration harness the JVM target
is what matters; bb/scittle compatibility becomes relevant only if
parts of the orchestrator are later moved into a bb runtime, or if
the chart itself needs to be runnable in a browser-side artifact for
documentation purposes.

For now, the recommended posture is:

1. **Sketch the chart in prose plus a textual diagram** before any
   implementation work begins, immediately after the EDN vocabulary
   is settled. The chart is then a paper artifact reviewable against
   the vocabulary.
2. **Encode the chart in clj-statecharts (or the bb-scittle fork) as
   data**, even if the orchestrator does not yet execute it. The data
   form is more precise than prose, can be diffed, and can be checked
   for structural properties.
3. **Optionally execute the chart at runtime** as the orchestrator
   matures. This converts the documentation artifact into a
   conformance guarantee.

Steps 1 and 2 are cheap and high-value. Step 3 is a larger
investment and can be deferred without giving up the documentation
benefit.

## Implementation plan

The plan is staged so that each stage produces a working artifact and
each stage's artifact is independently useful.

### Stage 0: data dictionary and EDN vocabulary

Before any code, capture the canonical names and structural
relationships of every entity in the system: actors, cryptographic
entities, persistent state, ceremonies, and events. The output is
`data-dictionary.edn` — a structured EDN file with namespaced
keyword identifiers for every entity, so all downstream artifacts
(this document, the statecharts, the implementation code) can
reference entities unambiguously.

Alongside the dictionary, the EDN message vocabulary captures the
wire form of the dictionary's `:event/*` entries when they travel
between the orchestrator and parties. Each event is shown as a
representative example with all relevant fields filled in. Together
they form the naming and message-shape contract the rest of the
system is built against.

Cost: half a day to a day. Output: `data-dictionary.edn` and the
EDN vocabulary appendix to this document.

### Stage 0.5: orchestrator-side ceremony statecharts

With the dictionary settled, define an orchestrator-side statechart
for each ceremony type (`:ceremony/keygen`, `:ceremony/sign`,
`:ceremony/reshare-recovery`, `:ceremony/reshare-divorce`,
`:ceremony/reshare-refresh`, `:ceremony/triple-generation`,
`:ceremony/presign`, `:ceremony/attestation-issuance`). Every event
in the dictionary should appear as a transition in at least one
chart; every state should have entry/exit actions tied to events
the dictionary defines. This is the consistency check that justifies
doing the dictionary and statecharts in sequence — either alone is
half the contract.

The charts are encoded in EDN data, in a form close to
clj-statecharts syntax with light shorthand for parallel-region
replication. Each chart is a separate file
(`statechart-<ceremony>.edn`). The charts can be used as
documentation artifacts without any orchestrator code yet running
against them; they may also be loaded at runtime by a clj-statecharts
execution engine if the orchestrator implementation goes that route.

The deliverable for each chart names every state a ceremony can be
in, every event that can move it between states, every guard that
restricts which transitions are legal, every entry/exit action the
orchestrator must perform when crossing a boundary, and a set of
structural properties the chart should satisfy (cancel handling,
final-state reachability, etc.). The cost of getting this wrong
scales: a missed transition discovered during Stage 4 testing is
worth ten of the same transition spotted during Stage 0.5 review.

Cost: half a day per ceremony chart, plus half a day for the
cross-cutting consistency review. Output: one
`statechart-<ceremony>.edn` per ceremony type, plus structural
property checks across the set.

### Stage 1: null orchestrator and null parties

Implement the orchestrator in Clojure and three "null" party processes
that speak the EDN vocabulary but contain no cryptography. The "null"
ceremony is a stub that the parties handshake through and immediately
report complete with placeholder values.

Three null parties exchange EDN messages through the orchestrator.
A "keygen" call to the orchestrator routes the lifecycle messages,
collects the (placeholder) results, and returns a map of (placeholder)
handles. No real cryptography happens. No Rust subprocess yet.

The purpose is to validate the routing logic, the EDN parsing and
generation, the orchestrator's ceremony-management state, and the bb
wrapper's stdio-handling — all at zero cryptographic cost. Failures at
this stage are about message shape and routing, not crypto, and are
much easier to diagnose.

Cost: one day. Output: a minimal Clojure project with three bb scripts
that round-trip a stubbed ceremony end-to-end.

### Stage 2: real keygen for one party only

Replace one of the three null parties with a real bb-wrapper plus
Rust binary that does actual threshold-signatures keygen. The other
two parties stay null but emit messages of the same shape (containing
plausible-looking but not real cryptographic blobs).

This will not produce a real key (you can't keygen with one real party
and two stubs that return random bytes), but it will exercise the
full bb-to-Rust stdio path, JSON message parsing, and share file
writing for one party. Failures here are about the bb-to-Rust
boundary — the EDN/JSON translation, the subprocess lifecycle, the
share-file persistence.

Cost: half a day. Output: one party that successfully spawns a Rust
keygen subprocess, processes its stdout, and writes a share file.

### Stage 3: real keygen for all three parties

Replace the other two null parties. Now keygen produces real shares,
all parties agree on a public key, and the orchestrator gets a map of
real handles.

This is the first end-to-end working ceremony. From here forward the
remaining work is mostly mechanical — the same patterns extend to
reshare and sign.

Cost: half a day (because most of the patterns are now in place).
Output: a working three-party keygen ceremony.

### Stage 4: reshare and sign

Add the reshare and sign ceremonies. Reshare is the UC2-specific
ceremony — keygen with member change. Sign is the validation that
post-reshare shares produce valid signatures.

The high-water mark for Stage 4 is the executable analog of the UC2
feasibility test: spawn three party processes, run a 2-of-3 keygen,
run a reshare with one member changed, verify the public key is
preserved, run a sign with the new shares, verify the signature
against the original public key. The same assertions as the UC2 test,
but now demonstrated across separated processes communicating
end-to-end.

Cost: one day for both ceremonies combined. Output: full UC2
end-to-end demonstration via the harness.

### Stage 5 and beyond: layer policy on top

Once cryptographic ceremonies work end-to-end, business logic begins
to accrete. Likely first additions:

- A Figure-side commitment registry, with commitment registration as a
  separate (non-cryptographic) ceremony.
- A commitment-gated reshare, where Figure-bb verifies a commitment-
  secret reveal before participating in resharing.
- A publication/objection window between commitment verification and
  reshare execution.

These build on the harness; they do not require structural changes.
At this point the architecture's payoff arrives — adding policy is
adding bb-side logic, not redesigning the orchestrator or the
cryptographic core.

Total cost through Stage 4: roughly three to four days of focused work.
Total artifact size: probably under 1500 lines of code combined
across orchestrator, bb wrappers, and Rust binary. Most of the line
count is in the Rust binary's stdio plumbing and the bb wrappers'
EDN-JSON translation.

## Open design questions

A few questions that are worth flagging now but do not block starting:

**Handle lifecycle semantics across ceremonies.** When a reshare
produces a new share, what happens to the old handle? Three options:
the old handle is invalidated automatically; the old handle stays
valid and the party stores both shares; the orchestrator explicitly
sends a "drop handle" message at the end of recovery. For exploration,
keeping old handles valid until explicitly dropped is most flexible
(re-runnable experiments). For production, automatic invalidation on
successful reshare is correct (no stale shares lingering). The harness
should default to keep-valid-with-explicit-drop and make the choice
configurable per ceremony.

**Failure semantics and timeouts.** The threshold-signatures crate
waits indefinitely for messages it expects. The orchestrator must
enforce timeouts. Per-ceremony deadlines are the natural granularity
— "this reshare must complete within N seconds, otherwise signal
cancel to all parties." The cancel signal is itself a message in the
EDN vocabulary, so this fits naturally. A more sophisticated approach
would distinguish slow-but-progressing from stuck, but exploration
does not need it.

**Error reporting granularity.** When a ceremony fails (bad
parameters, malformed message, party crash, signature verification
failure), how much detail should propagate up to the orchestrator and
the REPL? For exploration, more detail is better — surface the
underlying error from the Rust crate as a string in the EDN error
message. For production, careful thought about information leakage
through error messages becomes necessary, but it is not a concern at
this stage.

**Concurrency model.** Whether the orchestrator can drive multiple
ceremonies simultaneously, and what isolation guarantees apply if so.
For exploration, single-ceremony-at-a-time is the simplest and most
debuggable; multi-ceremony orchestration is a separate concern that
can be added later without breaking single-ceremony semantics.

**Real transport, eventually.** The orchestrator-as-simulator pattern
has the orchestrator routing messages between local subprocesses. In
production, parties communicate over real network transport (likely
with one party serving as ceremony coordinator, possibly a different
one per ceremony). The transition from simulator to real transport
should not require orchestrator changes — the orchestrator's job is
to send and receive EDN messages on a connection, and that connection
can be a subprocess pipe today, a TCP socket later, an HTTP endpoint
later still. The substitution stays behind the same EDN interface.

## Closing observation

The architectural payoff of this design is that the **EDN interface**
and the **ceremony statechart** together form a stable two-part
contract. The EDN interface specifies what messages flow between
parties; the statechart specifies what states the orchestrator passes
through in response to those messages. Either alone is half the
contract; together they are the full one.

Every other layer is replaceable behind this two-part contract. The
exploration harness can substitute its bb+rust party implementation
for a different cryptographic backend, a different runtime
environment, or a remote-process implementation, all without changing
the orchestrator. The orchestrator can be rewritten in any language
that speaks EDN-over-some-channel and conforms to the statechart,
without changing the parties.

Production deployment of the full recovery service can reuse this
contract as the agreement between Figure's recovery orchestrator and
the various parties' MPC node implementations, regardless of whose
party software is on the other end. That is the point: design the
contract carefully, implement on both sides freely, and let the
specification — vocabulary plus statechart — serve as the durable
artifact that survives implementation changes.

The contract is the architecture. The rest is engineering.

---

## Appendix A: The EDN message vocabulary (initial sketch)

This is a starting sketch of the message vocabulary. The canonical
event names (`:event/*`) and entity references (`:actor/*`,
`:ceremony/*`, etc.) are defined in `data-dictionary.edn`; the
message shapes here are the wire form of those events when they
travel between the orchestrator and parties. Stage 0 of the
implementation plan will refine these into the final form.

### Lifecycle messages (orchestrator → party)

```clojure
;; Begin a keygen ceremony.
{:msg/type :ceremony/begin-keygen
 :ceremony/id #uuid "..."
 :ceremony/me :holder
 :ceremony/peers [:holder :figure :ic]
 :ceremony/threshold 2
 :ceremony/scheme :ecdsa/secp256k1-ot-based}

;; Begin a reshare ceremony.
{:msg/type :ceremony/begin-reshare
 :ceremony/id #uuid "..."
 :ceremony/me :new-holder
 :ceremony/old-peers [:holder :figure :ic]
 :ceremony/old-threshold 2
 :ceremony/new-peers [:new-holder :figure :ic]
 :ceremony/new-threshold 2
 :ceremony/old-handle nil      ; nil if I'm a new participant
 :ceremony/public-key "0x04abcd..."}    ; required for continuity anchor

;; Begin a sign ceremony.
{:msg/type :ceremony/begin-sign
 :ceremony/id #uuid "..."
 :ceremony/me :new-holder
 :ceremony/peers [:new-holder :figure :ic]
 :ceremony/coordinator :new-holder
 :ceremony/handle #uuid "..."
 :ceremony/message-hash "0x..."}

;; Cancel an in-progress ceremony.
{:msg/type :ceremony/cancel
 :ceremony/id #uuid "..."
 :ceremony/reason :timeout}    ; or :user-abort, :error, etc.

;; Drop a stored handle (revoke a share).
{:msg/type :handle/drop
 :handle/id #uuid "..."}
```

### Protocol relay (bidirectional)

```clojure
;; Party emits a private message intended for one peer.
{:msg/type :protocol/private
 :ceremony/id #uuid "..."
 :protocol/from :figure
 :protocol/to :ic
 :protocol/body "<base64>"}

;; Party emits a broadcast message intended for all other peers.
{:msg/type :protocol/broadcast
 :ceremony/id #uuid "..."
 :protocol/from :figure
 :protocol/body "<base64>"}

;; Orchestrator delivers a message to a party.
{:msg/type :protocol/deliver
 :ceremony/id #uuid "..."
 :protocol/from :figure
 :protocol/body "<base64>"}
```

### Result and event messages (party → orchestrator)

```clojure
;; Ceremony complete with success.
{:msg/type :ceremony/complete
 :ceremony/id #uuid "..."
 :ceremony/result {:result/handle #uuid "..."         ; for keygen and reshare
                   :result/public-key "0x04abcd..."
                   :result/signature nil}}            ; populated for sign

;; Ceremony failed.
{:msg/type :ceremony/error
 :ceremony/id #uuid "..."
 :ceremony/error/category :bad-parameters
 :ceremony/error/message "..."}

;; (Optional) Heartbeat / progress.
{:msg/type :ceremony/progress
 :ceremony/id #uuid "..."
 :ceremony/progress/round 3
 :ceremony/progress/total 7}
```

The full vocabulary is approximately a dozen message shapes. Each
shape has an obvious EDN representation and an obvious JSON
counterpart for the bb-to-Rust boundary, where the binary protocol
body remains base64-encoded.

## Appendix B: JSON-on-stdio counterpart

The JSON wire format between bb and Rust mirrors the EDN vocabulary
with stylistic adjustments — kebab-case becomes snake_case,
namespaced keywords become string fields, UUIDs become strings, base64
bodies remain strings. The translation is mechanical and has no
semantic content.

For example, the EDN message:

```clojure
{:msg/type :protocol/private
 :ceremony/id #uuid "550e8400-..."
 :protocol/from :figure
 :protocol/to :ic
 :protocol/body "<base64>"}
```

becomes the JSON line:

```json
{"msg_type":"protocol_private","ceremony_id":"550e8400-...","from":"figure","to":"independent_custodian","body":"<base64>"}
```

The bb wrapper is responsible for this translation in both
directions. Note the Clojure-to-JSON convention: namespaced keywords
become snake_case strings (`:ic` →
`"independent_custodian"`), and the bare-actor name appears in JSON
since the namespace is implicit from the field name (`from` and `to`
fields contain actors, no other kind of value). The Rust binary
speaks only JSON.

## Appendix C: Out-of-scope concerns

For clarity about what this exploration harness does *not* address:

- Production-grade share storage (encryption, HSM, TEE).
- Real network transport (TLS, message authentication, replay
  protection at the transport layer).
- Authentication and authorization between parties (who is allowed to
  initiate a ceremony with whom).
- Production observability (structured logs, metrics, tracing).
- Performance optimization (the harness exists to validate
  correctness, not to be fast).
- Resistance to malicious party behavior beyond what the underlying
  threshold-signatures protocol provides at the cryptographic layer.
- Compliance, regulatory, and audit requirements.

Each of these is a real production concern, but each is independent
of the architectural decisions captured here, and each can be added
behind the same EDN interface without restructuring the system.

## Appendix D: Ceremony statechart sketch

This appendix gives a textual sketch of the orchestrator's per-
ceremony statechart, useful for orientation. The authoritative
statechart specifications now live in dedicated files alongside this
document:

- `statechart-keygen.edn` — the simplest ceremony, treated as the
  template that other ceremonies specialize.
- `statechart-sign.edn` — routine 2-party signing, with the IC
  offline. Adds an issuer-policy gate before any cryptographic work.
- `statechart-reshare-recovery.edn` — UC2 recovery, with the
  multi-party authorization gate (Figure and IC verify
  independently) and an optional objection window.
- Additional statechart files for divorce, refresh, and attestation
  issuance will be added in subsequent design passes.

The textual sketch below predates those files and is preserved for
narrative continuity. Where the sketch and the files disagree, the
files are authoritative.

### Top-level states

```
ceremony
├── :pending             initial state; ceremony record exists, no parties contacted
│       │
│       │ (event :command/begin)
│       ▼
├── :starting            entry: send :ceremony/begin-X to all parties
│       │
│       │ (all parties acked / first :protocol/* arrives)
│       ▼
├── :running             parallel region: one substate per party
│       │                  (see "Per-party substates" below)
│       │
│       ├──[ all parties in :party-done ]── ▶ :finalizing
│       │
│       ├──[ any party in :party-errored ]──▶ :aborting
│       │   or :command/cancel received
│       │   or wall-clock deadline elapsed
│       │
│       └── (:protocol/* messages cause routing actions
│            without leaving :running)
│
├── :finalizing          entry: collect per-party results;
│       │                       validate consistency (e.g., all parties agree
│       │                       on the public key after keygen/reshare)
│       │
│       │ (consistency checks pass)
│       ▼
├── :complete            FINAL state; orchestrator has the ceremony result;
│                        REPL caller is unblocked with the success value
│
├── :aborting            entry: send :ceremony/cancel to all parties;
│       │                       wait for ack or short timeout
│       │
│       │ (all parties acked or timeout)
│       ▼
└── :failed              FINAL state; orchestrator has the failure reason;
                         REPL caller is unblocked with the failure value
```

### Per-party substates (within :running)

```
party
├── :party-awaiting      waiting for the next :protocol/* message
│       │                from this party's Rust subprocess
│       │
│       │ (party emitted :protocol/private or :protocol/broadcast)
│       ▼
├── :party-relaying      transient; orchestrator routes the message
│       │                to recipient(s); side-effect, then back to awaiting
│       │
│       ▼
├── (back to :party-awaiting)
│
│       │ (party emitted :ceremony/complete with its result)
│       ▼
├── :party-done          terminal for this party in this ceremony
│
│       │ (party emitted :ceremony/error)
│       ▼
├── :party-errored       terminal-error for this party
│
│       │ (no message received within per-party timeout)
│       ▼
└── :party-timeout       terminal-error for this party (specific cause)
```

### Cross-cutting transitions

A few transitions deserve to be named explicitly because they are
easy to miss in a procedural rendering:

- **`:command/cancel` is legal in `:starting`, `:running`, and
  `:finalizing`.** Not in `:complete` or `:failed` (those are final).
  Not in `:pending` (no ceremony has actually started). Not in
  `:aborting` (already cancelling). The chart enumerates these
  explicitly rather than scattering the check through procedural code.

- **Wall-clock deadline expiry causes `:aborting`** from any
  non-final state. Modeled as a global guard tied to a timer set when
  the ceremony enters `:starting`.

- **A `:protocol/*` message arriving when the ceremony is in
  `:complete` or `:failed`** is dropped with a log entry, not an
  error — late-arriving messages from a party that hasn't yet seen
  the cancel are normal and should not corrupt orchestrator state.

- **A `:ceremony/complete` arriving from a party already in
  `:party-done`** is a protocol violation and should transition the
  whole ceremony to `:aborting` with a specific reason.

### Properties the chart should make obvious

Things that should be inspectable as structural properties of the
chart, separate from any executable behavior:

- Every non-final state has a transition for `:command/cancel`.
- Every non-final state has a transition for the wall-clock deadline.
- `:complete` is reachable only via `:finalizing`.
- `:failed` is reachable only via `:aborting`.
- `:running` cannot transition directly to `:complete` (must pass
  through `:finalizing` to perform consistency checks).
- The `:starting` state has a bounded duration (parties either ack or
  trigger a cancel-on-timeout); it is not a hold-forever state.

### Ceremony-type-specific specializations

The chart above is generic across keygen, reshare, and sign
ceremonies. Each specific ceremony type adds its own consistency
checks at the `:finalizing` step and its own per-party setup at the
`:starting` entry action:

- **Keygen finalization:** all parties must report the same public
  key. Different public keys → `:aborting`.
- **Reshare finalization:** all parties must report the *original*
  public key (continuity check). Any divergence → `:aborting`. This
  is the load-bearing UC2 invariant.
- **Sign finalization:** the coordinator's reported signature must
  verify against the public key referenced by the input handle.
  Verification failure → `:aborting`.

These specializations are entry actions on `:finalizing` rather than
separate states, because the structural lifecycle is identical across
ceremony types and the differences are in what counts as a valid
result. Modeling them as entry actions keeps the chart small.

### What this sketch deliberately omits

- Concurrency between ceremonies. The exploration harness assumes
  one ceremony at a time; multi-ceremony orchestration would add a
  parent statechart with ceremony-instances as parallel children, but
  is out of scope for the harness.
- Recovery semantics for a crashed orchestrator. If the Clojure
  process crashes mid-ceremony, the parties will time out and abort
  on their own; the orchestrator does not currently persist its
  state across crashes. This is acceptable for exploration.
- Reshare-specific "old participants who didn't continue" semantics
  beyond simple non-participation. The crate's API handles this
  cleanly (parties not in the new set don't run a protocol); the
  orchestrator only needs to *not* spawn protocols for them, which
  is a property of `:starting`'s entry action rather than a state in
  the chart.

The chart will be refined during Stage 0.5 against the EDN vocabulary.
This sketch is the seed, not the finished artifact.

## Appendix E: Confidentiality and transport architecture (Stage 5+)

Captures design decisions for the inter-party transport layer that the
harness defers (per Appendix C) but production needs. Recorded
2026-04-26 after a design discussion; concrete implementation is
Stage 5+ work.

### Message confidentiality

Per `Action::SendPrivate` in the threshold-signatures crate's
`Protocol` trait, the docstring is explicit: private messages MUST be
encrypted in transit. Broadcasts (`SendMany`) are not secret by design
(same bytes go to all peers). Our current harness routes both as
plaintext base64; that's deliberately out-of-scope (Appendix C).

Production approach: **end-to-end encrypted application-layer
sessions via the Noise Protocol Framework (XK pattern).** Each party
holds a static Curve25519 key; AKE at session start derives an
ephemeral session key; messages are AEAD-wrapped (ChaCha20-Poly1305
or AES-GCM).

Why Noise over mutual TLS:

- No PKI baggage (no CA management, no X.509).
- Forward secrecy comes for free.
- Mature support across ecosystems (`noise-rs`, JS Noise libs, Go).
- Simple state machine.

The trade-off: slightly less ubiquitous than TLS infrastructure for
non-cryptographic devops staff to operate.

Where this layer lives: **inside the bb wrapper**, between the
orchestrator-facing EDN boundary and the crypto-core stdio. The
wrapper:

- Holds the long-term static identity key.
- Establishes Noise sessions with peers at ceremony start.
- AEAD-wraps `protocol_broadcast` / `protocol_private` bodies before
  they leave the party; unwraps on receipt.
- The orchestrator (or production coordinator party) routes opaque
  bytes; the EDN contract is unchanged. Crypto-core is transparent
  to the layer.

This is exactly the substitutability the contract-first architecture
was designed for: encryption slots in behind the bb-wrapper boundary
without restructuring the orchestrator or crypto-core.

### Three keys per party (deliberately separated)

Production deployment introduces three distinct cryptographic
identities per party. They MUST be separate cryptographic objects:

1. **Identity signing key** (Ed25519, long-term). Authenticates
   "I am Figure" / "I am the holder." Registered in
   `:state/address-policy-registry` and possibly anchored on-chain.
   Long rotation cycle. HSM-backed in production.

2. **Transport encryption key** (X25519, possibly ephemeral session-
   derived). For confidentiality of inter-party messages. signet's
   Ed25519 ↔ X25519 birational conversion makes the same long-term
   entropy reusable across both, OR fully separate keys if preferred.

3. **MPC threshold share** (secp256k1 scalar). Wallet-specific share
   of the threshold-signature key. Never leaves the party. Stored
   per-wallet (per `:state/{role}-share-store`).

These are completely orthogonal cryptographic objects with different
storage requirements and rotation profiles. Mixing them creates
classical anti-patterns (signature oracles becoming decryption
oracles; Bleichenbacher-style attacks).

signet 0.4.0 already provides (1) and (2); the threshold-signatures
crate provides (3). The split is "free" in our codebase.

### Bootstrap trust

Two complementary mechanisms, both used together for YLDS:

1. **Onboarding-as-bootstrap.** Figure's existing KYC and contract
   onboarding establish initial pubkey bindings out-of-band. Each
   party stores peers' static Ed25519 pubkeys after onboarding. This
   reuses the trust establishment YLDS already mandates for
   regulatory reasons.

2. **On-chain anchor.** At wallet creation, the
   `:state/address-policy-registry` entry includes peers' identity
   pubkeys, anchored on Provenance Blockchain. Recovery and divorce
   ceremonies verify peer pubkeys against the on-chain anchor —
   gives a cryptographic root of trust independent of any one party.

Combination property: a compromised Figure cannot rewrite peer
identities (chain anchor); but the chain anchor reuses Figure's
KYC-established pubkeys (bootstrap reuse). Belt and suspenders.

### On-disk state confidentiality

All persisted state in `<role>/{shares,triples,presigs}/<handle>.bin`
contains secret material today (rmp-serde plaintext). Production
substitutes encryption-at-rest, OS keyring, HSM, or TEE-backed storage
at the bb-wrapper boundary. The `<role, handle>` API stays unchanged;
only the storage backend changes.

## Appendix F: Share-possession proofs and identity-share binding (Stage 5+)

Two related cryptographic primitives that production deployment will
need. Recorded 2026-04-26; Stage 5+ implementation. Both are small
additions with large architectural payoff.

### Share-possession proof

A standard Schnorr proof of knowledge over the per-party verification
share `X_i = x_i · G` — proves a holder controls their secret share
without producing a real signature.

```
Prover (holds x_i)              Verifier (knows X_i)
──────────────────              ────────────────────
pick random r ∈ Z_n
R = r · G
                  ─── R ──────►
                                 pick challenge c
                  ◄── c ──────
s = r + c · x_i
                  ─── s ──────►
                                 check s · G == R + c · X_i
```

Made non-interactive via Fiat-Shamir: `c = H(R || X_i || context)`.
Standard ~30 LOC of EC arithmetic on secp256k1.

**Distinct from "show that a multi-sig works":**

- Signing produces a real ECDSA signature → has consequences (commits
  the wallet, the bytes can be replayed in unintended contexts).
- PoK doesn't produce signature bytes → no replay risk in other
  contexts (with proper context binding).
- PoK is single-party, async → does not require ≥t parties online.
- PoK is free → does not consume a presignature.

Use cases unlocking from this primitive:

- **Aliveness check** before structural ceremonies — catches "share
  lost" failures before committing to a deadline-bound reshare.
- **IC onboarding** — Figure proves share-possession to IC.
- **Compliance / audit** — regulator-facing attestation that all
  designated share-holders are still in possession, without producing
  any real signatures.
- **Recovery-policy pre-gates** — surviving parties prove share-
  possession before initiating reshare.
- **Periodic share-health probe** — heartbeat-style, async,
  cheap.

The threshold-signatures crate's `PublicKeyPackage` exposes
verification shares; we'd propagate them through crypto-core's keygen
result up to the orchestrator's `:state/address-policy-registry`
entry.

This is a new ceremony: `:ceremony/share-possession-proof`. Single-
party, no protocol relay. Slots in alongside
`:ceremony/attestation-issuance`.

### Identity-share binding proof

Combined proof that one entity holds **both** a registered Ed25519
identity key AND a registered MPC share. Welds the two cryptographic
identities into a single verifiable transcript.

Construction (matching our existing primitives):

A Schnorr PoK of `x_i` with the Fiat-Shamir challenge derived from
both the verification share AND the Ed25519 identity key:

```
c = H(R || X_i || K_id_pub || verifier_nonce || ceremony_context)
s = r + c · x_i
```

The PoK is then signed with the Ed25519 identity key. Verifier checks
both the signature (against `K_id_pub`) and the PoK (against `X_i`).

**Critical property — non-transferability.** The Fiat-Shamir hash
bakes `K_id_pub` into `c`, so the PoK is locked to "the entity
controlling K_id_pub asserts that they control x_i." Without this
binding, Alice could intercept Bob's PoK and replay it under her own
identity.

What this unlocks (defense-in-depth):

- **Identity key compromise alone is insufficient** for MPC
  impersonation — attacker also needs the share (which is offline for
  IC most of the time).
- **Share compromise alone is insufficient** for identity-gated
  impersonation — attacker also needs the Ed25519 key.
- Compromise must include **both**, which is logically stronger.

Especially well-aligned with the offline-IC pattern: IC's Ed25519 key
can be online (handshakes, attestation issuance) while their share
stays offline. An attacker compromising only the online endpoint
fails the binding proof.

Production uses:

- **Ceremony handshake authenticator.** Every ceremony begins with
  each party producing a binding proof — cheap, async. Catches "valid
  identity but invalid share" mismatches before committing to a
  ceremony.
- **Noise session AKE augmentation.** The resulting session key is
  bound not just to the identity key, but to "identity AND share" —
  stronger session security.
- **Reshare validation.** New participants demonstrate their identity
  binds to their fresh post-reshare share.
- **Audit / compliance attestation** combining identity and
  share-possession in one transcript.

Implementation cost: ~50 LOC crypto-core (Schnorr-on-secp256k1) + ~30
LOC orchestrator (verify helper using signet for the Ed25519 sig + the
Schnorr verifier). Doesn't change the EDN or statechart contract.

**Stage 5 must-have**, not optional: small primitive, large
architectural payoff. The two-layer cryptographic gate it enables is
the right trust foundation for YLDS-scale regulatory contexts.

