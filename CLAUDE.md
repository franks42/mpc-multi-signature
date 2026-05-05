# CLAUDE.md — orientation for Claude Code

Welcome. This file orients you to the `mpc-multi-signature` project.
Read it once at the start of a session, then use the references in
`docs/` and `specs/` as you work.

## TL;DR

This repo will become an exploration harness for a multi-party MPC
wallet recovery system used by the YLDS tokenized-securities product.
The design work is largely done; this is now an implementation
project. The goal of the harness is to validate that the design
composes correctly across separated processes, with an EDN message
vocabulary and a statechart-driven orchestrator as the load-bearing
contract.

There are three layers, top-to-bottom:

1. **Pure Clojure orchestrator** (JVM). Drives ceremonies from a
   REPL, routes EDN messages between parties, enforces timeouts.
2. **Per-party harness** = bb wrapper + Rust subprocess. Three
   instances, one per party (holder, Figure, IC). bb handles EDN ↔
   JSON translation and party-specific business logic; Rust does the
   threshold-signature cryptography.
3. **Cryptographic core** in Rust, wrapping NEAR's
   `threshold-signatures` crate. JSON-Lines stdio interface. Identical
   binary across all three parties; differs only by `--role` flag.

The orchestrator and parties communicate in EDN. The bb wrapper and
Rust binary communicate in JSON-Lines on stdio. The contract between
orchestrator and parties is a two-part artifact: the EDN message
vocabulary plus the ceremony statecharts.

## Authoritative artifacts

These files are the source of truth. When in doubt, they win.

**`specs/data-dictionary.edn`** — every named entity in the system,
with namespaced keyword identifiers, role descriptions, and
cross-references. Read this first.

**`specs/statechart-*.edn`** (9 documentation charts) —
orchestrator-side ceremony lifecycles, written for human readers:
keygen, sign, reshare-recovery, reshare-divorce, reshare-refresh,
triple-generation, presign, share-possession-proof,
attestation-issuance.

**`specs/executable/statechart-*.edn`** (6 executable charts) —
the charts the runtime literally executes via `clj-statecharts`:
keygen, triple-generation, presign, share-possession-proof, sign,
reshare. The reshare chart covers all three reshare flavors
(recovery, refresh, divorce). The attestation-issuance ceremony
(TAS-driven, no MPC) does not yet have an executable chart and
remains future Stage 5c work.

**`docs/recovery-exploration-harness-design.md`** — architectural
rationale for everything: layer responsibilities, role asymmetry,
implementation plan in stages, EDN vocabulary appendix. Appendix E
and Appendix F (added 2026-04-26) capture Stage 5+ design decisions
for confidentiality/transport and share-possession proofs.

**`docs/statechart-best-practices.md`** — patterns guide for
writing executable ceremony charts. Read this before adding a new
ceremony. The `fsm/assign` gotcha (pattern #1, structurally
enforced via the `defaction` macro) is the single biggest trap;
the transport-vs-crypto routing distinction (pattern #4b) is
the second; the wait-state-vs-terminal-abort distinction (pattern
#10) is essential reading for Stage 5c work.

**`docs/policy-enforced-statechart-processing.md`** — architectural
design for how policy/authZ integrates into chart-driven ceremonies.
Read this before any Stage 5c work. Key concepts: implicit
decisions are real even before a PDP exists; chart owns *where*
decisions are made, PDP owns *what* they say; four-way decision
model (permit/deny/indeterminate/deferred — three from XACML, one
async extension); capabilities and PDP RPC calls are duals (same
trust roots, different locus); EDN, not XML.

**`docs/mpc-feasibility-spike.md`** — proves cryptographic
feasibility against NEAR's `threshold-signatures` crate with two
working tests. The Rust core's API is exercised here; consult before
writing your own Rust wrapper. (As of Stage 4 we are pinned to
`near/mpc` rev `a6e41e8`.)

**`docs/ylds-asset-recovery-use-cases.md`** and
**`docs/mpc-kyc-key-recovery.md`** — earlier domain memos. Background
for the problem, not implementation guidance. Skim once for context.

**Project memory** — durable cross-session state. Two key entries
to load via the MCP memory tool at session start:
search-tag `mpc-multi-signature,plan` for the live plan/status
(Stage 4 done, Stage 5 entry points), and `signet,encryption,
planned-enhancement` for the signet 0.5.0 work that lives upstream.

## Things the docs assume you understand

A few load-bearing concepts that matter for implementation choices:

**Bare-form vs namespaced keywords.** The dictionary uses `:actor/*`,
`:state/*`, `:ceremony/*`, `:event/*`, `:crypto/*` namespaced forms
because it catalogs heterogeneous kinds together. Code and wire
messages use bare forms (`:holder`, `:figure`, `:ic`, `:keygen`,
`:commitment-registry`) because context disambiguates. Both forms
denote the same entities.

**The IC is offline by default.** In a 2-of-3 wallet, routine
signing is performed by `{:holder, :figure}` only, with the IC
absent. The IC participates in keygen at wallet creation and in
structural ceremonies (recovery, divorce, refresh) but is offline
otherwise. This is enforced by the cryptographic protocol choice
(OT-based ECDSA, not robust ECDSA) and by the ceremony participant
lists.

**Public key as continuity anchor.** Recovery and divorce ceremonies
preserve the wallet's public key across share-set changes. The
dictionary's `:crypto/wallet-public-key` is the persistent identity
of a wallet; shares are subordinate to it. This is the load-bearing
UC2 invariant.

**Canonical participant-ids** (Stage 4 lesson). The threshold-
signatures crate's `KeygenOutput` has the integer participant-id
baked into the share. If the role↔int mapping drifts between
ceremonies — e.g. recomputed per-ceremony from `:ceremony/peers`
ordering — a post-reshare share will fail the next presign with
"received incorrect shares of additive triple phase". The
orchestrator owns ONE canonical mapping (registered at
`start-orchestrator` time, each role's index in `:roles` is its
stable id) and propagates it in every begin-* message. Stage 5+
work that introduces new ceremonies must follow the same convention.

**The orchestrator is harness-only.** It has no production analog.
In production, a transient "ceremony coordinator" role rotates among
the parties per ceremony. The EDN message vocabulary and statecharts
are designed to span both contexts unchanged; the orchestrator is
where exploration happens.

**Statecharts as implementation.** The chart files in
`specs/executable/` ARE the implementation — `chart_driven.clj`
loads them via `clj-statecharts`. Drift is mechanically impossible:
modifying the chart changes the runtime behavior immediately. The
documentation charts in `specs/` (without `executable/`) remain as
human-readable references and are covered by conformance tests.
When writing a new ceremony, the workflow is "write executable
chart → add ceremony-specific action(s) → add entry-point function" —
see `docs/statechart-best-practices.md` (especially the `fsm/assign`
gotcha in pattern #1).

## Implementation plan — staged

The plan is in `docs/recovery-exploration-harness-design.md` under
"Implementation plan". **Stages 0 through 5b are done as of
2026-04-28; the chart-driven runtime foundation (v0.6.0) shipped in
2026-04-28**. Stage 5c (business logic) is next.

Status at a glance:

- **Stage 0 (done)** — data dictionary + EDN message vocabulary.
- **Stage 0.5 (done 2026-04-26)** — all nine ceremony charts written
  in `specs/`: keygen, sign, reshare-recovery, reshare-divorce,
  reshare-refresh, triple-generation, presign,
  share-possession-proof, attestation-issuance. Each chart parses
  cleanly via `clojure.edn/read-string`. The threshold-ceremony
  charts share a common shape (specializing the keygen template);
  attestation-issuance has a distinct shape (TAS-driven, no MPC).
- **Stage 1 (done)** — null orchestrator + three null parties round-
  tripping a stubbed `:keygen` ceremony in EDN. Tag
  `v0.1.0-stage-1-null-orchestrator`.
- **Stage 2 (done)** — bb wrapper + Rust crypto-core plumbing
  validated for one party with two stubs. Tag
  `v0.2.0-stage-2-bb-rust-plumbing`.
- **Stage 3 (done)** — all three parties bb+rust; first end-to-end
  real keygen with persisted shares (rmp-serde + SHA-256
  fingerprint). Tag `v0.3.0-stage-3-real-keygen`.
- **Stage 4 (done)** — UC2 high-water mark: keygen → reshare-with-
  member-change → sign with new shareset → independent cross-verify
  via signet/BC against the original public key. Tag
  `v0.4.0-stage-4-uc2-complete`.
- **Stage 5a (done)** — share-possession + identity-share binding
  proofs (per design doc Appendix F). Schnorr PoK on each party's
  verification share `X_i = x_i·G` welded to their Ed25519 identity
  via bound challenge context + Ed25519 signature over the
  transcript. Independent BC-based verifier in pure Clojure.
  Tag `v0.5.0-stage-5a-share-possession-binding`. Concrete signal:
  every party now has a cryptographically welded identity-share
  pairing — the trust foundation for everything downstream.
- **Stage 5b (done)** — transport hardening (per design doc
  Appendix E): Noise_KK pairwise sessions in the bb wrapper using
  the same Ed25519 identity keys provisioned in Stage 5a (auto-
  converted to X25519 via signet's birational map). AEAD-wrapped
  protocol bodies. Encryption-at-rest for share/triple/presig files
  at the bb-wrapper boundary. Identity-key placement migrated from
  orchestrator to bb wrapper (production placement: orchestrator
  only sees announced pubkeys). Tag `v0.5b-stage-5b-complete`.
- **Chart-driven foundation (done 2026-04-28)** — six executable
  charts in `specs/executable/` drive the entire ceremony lifecycle
  via `clj-statecharts`. The chart IS the implementation; drift is
  mechanically impossible. Six per-ceremony smoke runners in
  `orchestrator/dev/smoke_chart_driven_*.clj` exercise each end-to-
  end with real Noise sessions + crypto-core; final signatures
  cross-verify against original wallet pubkeys. Patterns doc:
  `docs/statechart-best-practices.md`. Tag
  `v0.6.0-chart-driven-foundation` (initial keygen + triple-gen);
  presign, share-possession-proof, sign, reshare added in follow-up
  commits on the same branch. The procedural `ceremony.clj` was
  fully subsumed and deleted.
- **Stage 5c (next)** — traditional business-logic scope:
  commitment registries, commitment-gated reshare,
  publication/objection windows, multi-party authorization gates for
  recovery, attestation-issuance ceremonies (KYC TAS, commitment
  TAS, social recovery TAS). New ceremonies now reduce to writing an
  executable chart in `specs/executable/` + a thin entry-point
  function with `make-begin` and `build-result` in
  `orchestrator/.../chart_driven.clj`.

Stage 5b prerequisites already shipped: **signet 0.5.0** (in `~/.m2`
+ `github.com/franks42/signet` tag `v0.5.0`) provides
`signet.encryption/box` and `unbox` — sender-authenticated AEAD
(X25519 DH → HKDF-SHA-256 → ChaCha20-Poly1305). JCA-only,
bb-compatible. Auto-converts Ed25519 keypairs so the same identity
keys provisioned in Stage 5a drop straight into transport
encryption with no separate key plumbing.

Architecture invariants locked in Stages 1–4 (carry forward):

1. `party/` and `crypto-core/` are SINGLE codebases used by all roles
   — only the `--role` flag differs. Don't fork them per party.
2. **Canonical role↔int participant-id mapping** is registered at
   `start-orchestrator` time (each role's index in `:roles` is its
   stable id). Threshold-signatures shares are bound to specific
   integer ids; if those drift between ceremonies, presign rejects
   with "received incorrect shares of additive triple phase".
3. Triple-generation, presign, sign, reshare are SEPARATE ceremonies
   with persisted intermediates between phases (per the dictionary's
   `:ceremony/*` decomposition). Sets up Stage 5+ triple-stockpiling
   for free.
4. Reshare protocol-runner rule: only `new_participants` run the
   reshare Protocol (per cait-sith). Old-only participants are
   referenced via `old_participants` metadata in the begin message
   but don't exchange protocol messages.
5. The orchestrator has no production analog. In production, a
   transient ceremony-coordinator role rotates among the parties per
   ceremony. EDN vocabulary + statecharts span both contexts
   unchanged (same contract, different process).

Spec issues fixed 2026-04-26 (all three statechart EDN files now
parse cleanly via `clojure.edn/read-string`):

1. Duplicate `:event/ceremony-complete` keys in `:state/running`'s
   `:on` map (and the analogous duplicate `:event/both-gates-passed`
   in reshare-recovery's `:state/authorization-gate`): collapsed into
   a single key whose value is a vector of guarded transitions
   evaluated in order. Same semantic intent, valid EDN +
   clj-statecharts shape.
2. The `{:like :region/holder :substitute-actor X}` shorthand was not
   real `clj-statecharts` syntax (and reshare-recovery referenced a
   `:region/holder-template` that was never defined). Each parallel
   region is now expanded inline with the appropriate
   `(guard/originated-from :actor/X)` substitution.
3. Design doc Appendix A's `:ceremony/error/category`,
   `:ceremony/error/message`, `:ceremony/progress/round` and
   `:ceremony/progress/total` (multi-slash keywords, invalid EDN) now
   use the nested-map form already used by the implementation:
   `:ceremony/error {:category ... :message ...}` and
   `:ceremony/progress {:round ... :total ...}`.

## Implementation hints

A handful of decisions that would otherwise need to be re-derived
each time someone reads the docs.

**Project layout.** Create directories as needed:
```
mpc-multi-signature/
├── docs/                       # design docs (already exists)
├── specs/                      # dictionary + statecharts (already exists)
├── orchestrator/               # JVM Clojure orchestrator
│   ├── deps.edn
│   └── src/...
├── party/                      # bb wrapper used by all three parties
│   ├── bb.edn
│   └── src/...
├── crypto-core/                # Rust binary used by all three parties
│   ├── Cargo.toml
│   └── src/...
└── scripts/                    # convenience shell scripts
```

The same `party/` and `crypto-core/` are used by all three parties;
role differences are configuration, not separate codebases. Don't
fork them per party.

**Dependencies for the orchestrator.** Start minimal: Clojure 1.12,
core.async (or manifold; pick one and stick), `clj-statecharts` (or
the bb-scittle fork), `tools.deps`, an EDN reader (built-in), a
process-spawn library if you need one (java.lang.ProcessBuilder is
fine; doesn't need a wrapper for this scale). Avoid frameworks; this
is a small focused harness.

**Dependencies for the bb wrapper.** Babashka has most of what's
needed in stdlib. EDN reading and writing, JSON via
`cheshire.core`, process spawning via `babashka.process`. No
framework needed.

**Dependencies for the Rust binary.** Look at
`docs/mpc-feasibility-spike.md` Appendix B (the
`ot_offline_custodian.rs` test) for the API surface. Add `serde_json`
for JSON-Lines parsing, `base64` for binary encoding, and one of
`clap` / `argh` / hand-rolled for CLI argument parsing. Pin the
threshold-signatures crate to a specific commit of `near/mpc` for
reproducibility.

**Stdio framing for bb ↔ Rust.** JSON Lines: one JSON object per
line, newline-delimited, no trailing comma. Each message has at
minimum `{"msg_type": ..., "ceremony_id": ...}`. Binary protocol
bodies are base64-encoded strings. The bb wrapper reads from the
Rust subprocess with a line-buffered reader; do not try to use
length-prefixed binary at this stage.

**Share storage.** Plaintext files in a per-party directory:
`./holder/shares/<handle>.bin`, `./figure/shares/<handle>.bin`,
`./ic/shares/<handle>.bin`. Handles are UUIDs generated by the party
when the share is produced. The orchestrator never sees share
contents.

**REPL ergonomics.** The orchestrator's primary interface is the
REPL. Ceremony functions should be blocking from the REPL's
perspective: `(keygen orch [:holder :figure :ic] {:threshold 2})`
returns a result map after the ceremony completes. Internally use
core.async or promises; externally keep the call synchronous. Don't
make REPL users deal with async unless they ask for it.

**Statechart execution.** Decided: **the chart IS the implementation.**
`orchestrator/.../chart_driven.clj` loads each chart in
`specs/executable/` via the translator at
`orchestrator/.../chart_runtime.clj` and feeds the resulting FSM
(via the `franks42/clj-statecharts-bb-scittle` fork) ceremony events
from the bb wrappers. Drift between chart and code is mechanically
impossible because they are the same thing.

When writing a new ceremony, follow `docs/statechart-best-practices.md`.
Pattern #1 is non-obvious and costs hours if missed: every action
that updates context must be wrapped with `(fsm/assign ...)`; plain
return values are silently discarded.

For docs-grade reading the original `specs/statechart-*.edn` charts
remain canonical (more poetry, illustrate parallel regions etc.);
the executable variants in `specs/executable/` are sparser and
hew to clj-statecharts execution semantics. Conformance tests
(`orchestrator/test/.../chart_conformance_test.clj`) cover the
documentation charts and provide drift-detection between
documentation and execution-correct shapes.

**Don't yet build:** persistent state across orchestrator restarts,
multi-ceremony concurrency, real network transport, encryption at
rest, authentication between parties, or anything else listed in
"Out-of-scope concerns" (Appendix C of the architecture doc). The
harness exists to validate cryptographic and structural composition,
not to be a production system.

## Tooling conventions

A handful of non-negotiable conventions for Clojure/bb code in this
repo. Two sibling projects sit alongside this one and serve as the
reference for how to use the shared utilities:

- `../uuidv7.cljc/` — the timestamped-UUID library used for all
  identifiers in this project (ceremony ids, share handles,
  correlation ids).
- `../bb-mcp-server/` — a working bb project that demonstrates how
  trove, uuidv7, bb tasks, and statecharts are wired together.
  Consult this before writing equivalent code from scratch; the
  patterns there are the patterns we want here.

**Always run clj-kondo and cljfmt after every edit.** No exceptions.
Warnings are not acceptable — resolve all of them before reporting an
edit complete. This applies to every Clojure source file the harness
touches (orchestrator `.clj`, party `.bb`/`.clj`, `bb.edn`, `deps.edn`).
A clean lint pass is part of the deliverable; a passing test with
lint warnings is not done.

**Use `../uuidv7.cljc` for all UUIDs.** Every identifier in this
project — ceremony ids, share handles, correlation ids, anything that
would otherwise be a `random-uuid` — uses the v7 timestamped form
from this sibling library. The timestamp prefix is operationally
useful (sortable logs, ordered ceremony histories) and the cost is
zero. Don't reach for `java.util.UUID/randomUUID` or `(random-uuid)`.

**Use trove for instrumentation and logging everywhere.** Both the
orchestrator and the bb wrappers emit structured events through
trove, not `println` or `clojure.tools.logging`. This is a debugging
harness first; structured, queryable events are the deliverable, and
trove's per-ceremony correlation is exactly the shape we need.
`../bb-mcp-server/` shows the patterns — consult it before guessing
at API shape.

**Use bb tasks instead of bash scripts.** Anything that would
otherwise live as `scripts/foo.sh` belongs in `bb.edn` as a `:tasks`
entry. The `scripts/` directory in the project layout above is for
the rare case where bash is genuinely the right answer (and even
then, prefer bb). `../bb-mcp-server/bb.edn` has many examples of the
shape and conventions to use.

## Working style

A few things that will make our collaboration smoother.

**When in doubt, search the specs.** The dictionary entries and
statecharts are designed to answer "what is this entity, what does
it do, what does it interact with." If a question would be answered
by reading those files, read them rather than asking.

**When the spec is silent, ask.** Don't invent. Many design choices
were made deliberately and the spec captures the conclusion, not
the rejected alternatives. If you can't find the answer in the
specs, ask before guessing — the answer is usually simple but
wrong-guess is expensive.

**When the spec contradicts itself, flag it.** It's not finished.
Specifically: the spec is at version 0.1.0 and the dictionary's
status is `:draft`. Inconsistencies between the dictionary and the
statecharts, between the statecharts and the architecture doc, or
between any of those and prior memos exist and are bugs. Surface
them; don't paper over them.

**Test as you go.** Each stage produces a working artifact. Don't
write a full implementation of Stage 1 before any of it runs;
build the smallest piece that exchanges one EDN message
end-to-end, get it working, then add features. The Stage 1 null
orchestrator should be runnable within an hour of starting it.

**Error messages and logs are part of the deliverable.** This is a
debugging tool first; performance comes much later. Spend effort on
clear failure messages that say which actor, which ceremony id,
which event, and what was expected. A failure in Stage 4 that says
"protocol error in figure-bb" is much less useful than "ceremony
abc-123 (reshare-recovery): figure-bb rejected attestation
verification, reason: signature invalid for tas-id kyc-tas-1."

**Honesty over confidence.** If you're unsure whether something
will work, say so before doing it; if it didn't work the way you
expected, say so before claiming success; if you don't understand
why a test passes, that's information worth surfacing. The previous
sessions that produced this design were valuable specifically
because they distinguished "verified" from "expected" from
"assumed." Carry that forward.

## Stage 5c entry points

Stages 0–5b plus the chart-driven runtime foundation are done
(tag `v0.7.0`). External LLM review was applied (tag `v0.7.1`):
`defaction` macro now wraps `fsm/assign` structurally, action
names are generic, conformance tests retargeted to executable
charts (12 tests / 119 assertions on `specs/executable/`).

**Policy-enforcement design** (added late April 2026 — read this
before any 5c work) is in `docs/policy-enforced-statechart-processing.md`.
Summary of the design choices that need to be honored:

- **Decision model is four-way: permit / deny / indeterminate /
  deferred.** Three from XACML; deferred is the async extension.
  `:permit` advances; `:deny` terminates with `:outcome :rejected`
  in the result payload; `:indeterminate` terminates with
  `:outcome :error`; `:deferred` holds in the gate state pending
  external answer.
- **Gates are real chart states**, not transition guards.
  `:state/begin-authorization` (after `:state/pending`, before
  `:state/starting`) is universal across all ceremonies. Reshare-
  flavored ceremonies add `:state/authorization-gate` later.
- **Trivial PDP first.** A stub PDP returning permit/deny/etc.
  by mode flag lands before any real policy logic. Chart shape
  stays stable as the PDP grows.
- **EDN throughout, not XML.** XACML's encoding pain is the
  one thing we *don't* inherit.
- **Capabilities and PDP RPC calls are duals** — same trust
  roots, same verification, different choice of where the
  decision is materialized. The chart doesn't distinguish.
- **`:state/failed` is a single terminal state**; the result
  payload's `:outcome` keyword distinguishes
  `:rejected | :error | :aborted | :canceled`.

**Stage 5c — business logic.** Substages, in order:

1. **5c.0a — PDP scaffolding.** Add `policy.clj` (mode-flag stub),
   add `:state/begin-authorization` to all 6 executable charts,
   wire dispatch action + four decision events, add a smoke
   exercising both permit-all and deny-all modes, add a
   conformance assertion that `:state/starting` is unreachable
   except via the gate. **This is the immediate next step.**
2. **5c.0b — Foundational-principle compliance.** IC pubkey
   user-supplied at keygen (not Figure-default); KYC TAS as
   separate principal type with own pubkey in address-policy.
3. **5c.1 — Persistent registries.** Address-policy + commitment
   registries that survive orchestrator restarts.
4. **5c.2 — Attestation-issuance ceremonies.** TAS as fourth-
   party type. PDP starts validating attestation signatures —
   first non-trivial policy evaluation.
5. **5c.3 — Multi-party authorization gates.** Reshare-flavored
   ceremonies grow `:state/authorization-gate`. Real declarative
   policy DSL (likely `stroopwafel`-driven) replaces the trivial PDP.
6. **5c.4 — Objection windows.** First ceremony with a real wait
   state (per pattern #10).
7. **5c.5 — End-to-end UC2 with policy gating.** The first
   ceremony the system can REFUSE.

Adding a new ceremony reduces to:

1. Write the executable chart in `specs/executable/<name>.edn`,
   following `docs/statechart-best-practices.md` (especially the
   `fsm/assign` / `defaction` gotcha in pattern #1 and the
   wait-state pattern in pattern #10).
2. Add ceremony-specific actions to
   `orchestrator/.../chart_driven.clj` if finalization needs them
   (most ceremonies reuse `check-results-collected`; add a
   `<name>-consistency-check` if you have a real cross-party
   check via `defaction`).
3. Add a `run-<name>-via-chart` entry point with `make-begin` and
   `build-result` closures.
4. Add a smoke runner in `orchestrator/dev/`.
5. **From 5c.0a onward**: ensure the chart includes
   `:state/begin-authorization` after `:state/pending`, routing
   the four PDP decisions correctly.

**Working entry pattern for a fresh session:**

1. Read this file (orientation).
2. `mcp__memory__memory_search` for tag `mpc-multi-signature,plan`
   for the latest plan/status memory; for tag
   `mpc-multi-signature,statechart,clj-statecharts,best-practices`
   for the chart-driven runtime patterns; for tag
   `signet,planned-enhancement` for the signet roadmap.
3. **For 5c work, read `docs/policy-enforced-statechart-processing.md`
   first** — it captures the architectural decisions (decision
   model, trust-roots view, capability/PDP unification) that will
   shape every 5c ceremony.
4. Also skim `docs/statechart-best-practices.md` if you'll be
   writing a chart; `docs/recovery-exploration-harness-design.md`
   Appendix E + F for transport / share-possession architecture.
5. `git log --oneline -20` for the recent narrative. Most recent
   tag: `v0.7.1-review-feedback-applied`.
6. Pick a Stage 5c sub-piece — start with 5c.0a unless you have
   reason to skip ahead.

Good luck. Ask early, test often.
