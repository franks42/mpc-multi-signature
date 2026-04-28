# Read before review

> **Audience:** LLM code reviewers (GPT, Gemini, etc.) examining the
> `mpc-multi-signature` project at the merge of branch
> `feat/chart-runtime-poc` to `main` (tag
> `v0.7.0-all-ceremonies-chart-driven`).
>
> **Purpose:** focus your attention. This is a multi-language,
> multi-process system with a long iteration history; without
> guidance you will spend tokens on plumbing that already works
> instead of the part that wants review.

## What changed (the part to review)

The branch is one architectural shift: every threshold-MPC ceremony
in the project (keygen, triple-generation, presign, sign,
share-possession-proof, reshare/recovery/refresh/divorce) was migrated
from a procedural Clojure runtime to a **chart-driven runtime** that
literally executes orchestrator-side ceremony statecharts via
`clj-statecharts`. The chart IS the implementation; drift between
chart and code is mechanically impossible.

The old procedural `ceremony.clj` (485 lines) was deleted. The new
runtime fits in two files (`chart_driven.clj`, `chart_runtime.clj`)
plus six EDN charts under `specs/executable/`.

## What's load-bearing — read these in order

If you read **only five things**, read these:

1. **`docs/statechart-best-practices.md`** (~300 lines)
   The 9 patterns the implementation embodies. The most useful
   single artifact for review — every non-obvious choice is
   articulated here, with the *why*.

2. **`orchestrator/src/.../chart_runtime.clj`** (257 lines)
   Project-EDN → clj-statecharts spec translator. Pure code, no
   side effects, no FSM execution. Translates project conventions
   (`:statechart/states`, `:statechart/parallel-regions`,
   list-form guards, `:auto` eventless transitions) into the shape
   `(statecharts.core/machine ...)` accepts.

3. **`orchestrator/src/.../chart_driven.clj`** (720 lines)
   The runtime. Action registry, guard registry, FSM event loop,
   six per-ceremony entry points. The most interesting parts:
   - `run-chart-fsm!` — generic driver
   - `:action/...` registry entries — one per chart action
   - `keygen-consistency-check`, `sign-consistency-check`,
     `reshare-consistency-check` — `fsm/assign`-wrapped actions
     that combine context update + synthetic event queueing
   - `run-<name>-via-chart` — six entry points with per-ceremony
     `make-begin` and `build-result` closures

4. **One executable chart** — pick `specs/executable/statechart-keygen.edn`
   (157 lines) as a representative. The other five follow the same
   shape with ceremony-specific finalization.

5. **`docs/chart-runtime-poc-findings.md`**
   The story: first attempt failed (drove documentation charts
   directly), what we learned, what the second attempt did
   differently. Helps you understand the patterns by seeing the
   anti-patterns we hit.

## What to skip

These work and don't need review attention:

- **`party/src/mpc_multi_signature/party/core.clj`** (~800 lines).
  The bb-wrapper. Stable since Stage 5b. Handles Noise_KK pairwise
  sessions + crypto-core subprocess management. Read only if you
  want context on what the orchestrator's `:protocol/private`
  routing carries.

- **`crypto-core/`** (Rust, NEAR threshold-signatures wrapper).
  Wrapped in JSON-Lines stdio. Stable.

- **`specs/statechart-*.edn`** (9 documentation charts at top of
  `specs/`, NOT under `executable/`). These are intentionally
  human-readable and contain idioms (parallel regions for
  documentation flourish, external self-loops on parents) that
  *would not execute correctly*. They diverge from the executable
  charts on purpose. The findings doc explains why.

- **`docs/recovery-exploration-harness-design.md`** — original
  architectural rationale; valuable for context but not the
  thing under review.

- **`docs/trust-and-policy.md`** — trust/policy spec; relevant
  to Stage 5c (next), not to the chart-driven runtime.

- **Sibling libraries** (`../signet`, `../uuidv7.cljc`,
  `../bb-mcp-server`, `../clj-statecharts-bb-scittle`). The fork
  of `clj-statecharts` is in active use; the others are stable
  utilities.

- **Smoke runners** (`orchestrator/dev/smoke_*.clj`). Each runs
  one ceremony end-to-end with real bb wrappers and crypto-core.
  Useful as executable specs of the public API; not the place
  for review depth unless you want to verify cross-verification
  semantics.

## Architectural framing

This is a **harness**, not a production system. The orchestrator
has no production analog — it exists to drive ceremonies from a
REPL with full visibility. In production, a transient
"ceremony coordinator" role rotates among the parties per
ceremony. **The EDN message vocabulary and statecharts span
both contexts unchanged** — that's the load-bearing architectural
choice.

Three layers (top to bottom):

1. **Pure Clojure orchestrator** (JVM). Drives ceremonies, routes
   EDN messages, enforces timeouts. Owns the chart-driven runtime.
   The part under review.

2. **bb wrapper** (per party). EDN ↔ JSON-Lines translation, Noise
   transport, encryption-at-rest. Stable.

3. **Cryptographic core** (Rust). Threshold ECDSA via NEAR's
   threshold-signatures. JSON-Lines stdio. Stable.

## What we want feedback on

Open-ended, but here are angles where outside eyes are most likely
to spot something we missed:

1. **Is the action-registry abstraction the right one?** The chart
   names actions by keyword (`:action/route-message`); the registry
   maps keyword → fn. Several keywords alias the same fn (e.g.
   `:action/triple-shape-check` and `:action/presig-shape-check`
   both → `check-results-collected`). Is this clean, or would
   genericizing the keyword be better?

2. **`fsm/assign` for context updates** is the killer gotcha
   (pattern #1). We document it heavily but don't avoid it. Is
   there a saner wrapper we should write so callers don't have to
   remember? E.g., a `defaction` macro that auto-wraps?

3. **Plumbing context** uses double-colon `::keys` (`::orch`,
   `::pending-events`, etc.). Is this idiomatic, or should
   plumbing be threaded differently (e.g. dynamic vars, a
   ceremony-handle record)?

4. **Per-ceremony entry points** (`run-keygen-via-chart`,
   `run-sign-via-chart`, ...). Each is a thin wrapper supplying
   ceremony-specific `make-begin` and `build-result`. Could
   these be data-driven? Worth it?

5. **Conformance tests** cover the *documentation* charts in
   `specs/`, not the executable charts. They were the drift-
   detection foundation in the first POC attempt. Now that the
   doc charts and executable charts intentionally diverge,
   what *should* the conformance tests cover? Should they be
   refocused to verify the executable charts cover every event
   the dictionary defines?

6. **The 9 patterns** in `docs/statechart-best-practices.md` —
   are any of them really sub-patterns? Could the list be
   collapsed without losing the load-bearing rules? Conversely,
   are any patterns missing — anything you'd predict will bite
   us when adding Stage 5c business-logic ceremonies?

7. **Anti-patterns we hit and avoided** — does the patterns doc's
   anti-pattern table miss anything obvious from the chart-driven
   approach we should warn future readers about?

## Useful entry points to verify behavior

Six per-ceremony smoke runners under `orchestrator/dev/`:

- `smoke_chart_driven_keygen.clj` — 3-party DKG with consistency check
- `smoke_chart_driven.clj` — triple-generation
- `smoke_chart_driven_presign.clj` — presignature
- `smoke_chart_driven_share_proof.clj` — Schnorr PoK, plain + binding mode
- `smoke_chart_driven_sign.clj` — ECDSA signing (asymmetric result)
- `smoke_chart_driven_reshare.clj` — UC2 mechanism (divorce-style)

Plus two legacy smokes (`smoke_5b2.clj`, `smoke_refresh_divorce.clj`)
that exercise the public API in `orchestrator.core/...`, which now
runs through the chart-driven runtime internally.

Conformance tests:
`orchestrator/test/.../chart_conformance_test.clj` (10 tests,
50 assertions; all pass).

## Iteration history (so you don't relitigate decided choices)

- The first POC attempt drove the *documentation* charts directly
  via clj-statecharts and *failed* — the docs charts had
  decorative parallel regions, external self-loops on parents,
  and dead sub-states that broke under execution. See
  `docs/chart-runtime-poc-findings.md`.

- The second attempt (this branch) wrote *new* charts in
  `specs/executable/` that follow execution-correct patterns.

- Pattern #1 (fsm/assign) was the highest-cost gotcha. Pattern
  #4b (transport-vs-crypto routing) was discovered when
  share-possession-proof's "no peer-to-peer crypto" chart broke
  the Noise handshake routing.

- Three of four follow-up ceremony migrations after the
  foundation worked **first-try**, no debugging round — evidence
  the pattern set has stabilized.

## What's next (so reviews can be timely)

Stage 5c business logic — commitment registries, attestation-
issuance ceremonies, multi-party authorization gates. These
will use the chart-driven runtime as foundation. Reviews most
useful *now* would surface patterns or gaps that affect 5c work.

Out of scope for this review: switching the cryptographic backend
(planned migration to silent-shard-dkls23-ll), persistent state
across orchestrator restarts, real network transport.

---

Thanks for taking time on this. The chart-driven runtime works,
but "works" and "would survive Stage 5c gracefully" are different
claims; the second is where outside review pays off.
