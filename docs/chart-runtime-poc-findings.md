# Chart-Driven Runtime POC — Findings

> **Branch:** `feat/chart-runtime-poc`. The POC succeeded on a
> second-generation approach. This document records what we learned
> across two attempts and the recommended path forward.

## Goal

Test whether the orchestrator's ceremony lifecycle could literally
*execute* the statechart EDN definitions in `specs/`, rather than
just conform to them. If so, drift between chart and code becomes
mechanically impossible — the chart **is** the implementation.

## Outcome — success on the second attempt

Two ceremonies now drive end-to-end through the chart-driven runtime:

- **Triple-generation (2 parties).** Smoke runner
  `orchestrator/dev/smoke_chart_driven.clj`. Drives keygen
  (procedural) → chart-driven triple-gen → procedural presign +
  sign → cross-verify against the wallet pubkey. Green.
- **Keygen (3 parties, real consistency check).** Smoke runner
  `orchestrator/dev/smoke_chart_driven_keygen.clj`. Drives
  chart-driven keygen → procedural triple-gen + presign + sign →
  cross-verify against the *chart-driven keygen's* reported pubkey.
  Green. **First-attempt success** once the patterns from the first
  ceremony were applied.

The patterns that made it work — and the ones that broke the first
attempt — are documented in `docs/statechart-best-practices.md`.

## What the first attempt taught us

The initial attempt tried to drive the *documentation* charts
(`specs/statechart-*.edn`) directly via clj-statecharts. The
translator (`orchestrator/src/.../chart_runtime.clj`) was correct,
but the charts contained idioms that read naturally as English yet
fail under clj-statecharts execution semantics:

1. **Self-loops on parallel parents** (`:state/running →
   :state/running` on every protocol message). External transitions
   exit and re-enter the state, resetting parallel regions to their
   initial substate.
2. **Per-region entry actions duplicating parent's transition
   actions.** Both fired, leading to double-routing of protocol
   messages and AEAD-tag failures from Noise nonce desync.
3. **Dead `:done`/`:errored` sub-states** that no transition ever
   reached — readable as documentation, structural noise to an
   executor.
4. **Notation mismatch between charts and runtime.** Charts used
   `:actor/holder`; runtime used `:holder`. Required a bridge.
5. **Silent context-update discard.** Actions returning a modified
   state map have their changes ignored unless the return value is
   wrapped in `(fsm/assign ...)` — the killer gotcha that costs
   hours.

The first-attempt artifacts (`chart_driven_ceremonies.clj`,
`smoke_chart_driven.clj` in their pre-rename form) have been
removed; the lessons distilled to the patterns doc.

## What the second attempt did differently

Designed *new* charts for execution, in `specs/executable/`. The
patterns:

- No parallel regions when they have no transitions to reach
  (`:done`/`:errored` decoration in the documentation charts is
  decoration). Per-party state lives in
  `:ceremony/per-party-state` context.
- Internal transitions (no `:target`) for in-state events that
  don't change state. Confirmed by clj-statecharts source: nil
  `:target` skips entry/exit and parallel resets.
- Bare keyword namespace at the chart/runtime boundary. No bridge.
- All context-updating actions wrapped in `(fsm/assign ...)`. Pure
  side-effect actions return state unchanged.
- Synthetic events via a pending-events atom queue, drained by the
  driver between FSM transitions.
- Ceremony-specific behavior (begin-message shape, success-result
  shape) injected as functions in plumbing context (`::make-begin`,
  `::build-result`) so the chart actions stay generic across
  ceremonies.

## Recommendation

**Merge `feat/chart-runtime-poc` to `main` as the foundation for
future ceremony work.** Specifically:

- Keep the executable charts under `specs/executable/`
  (`statechart-keygen.edn`, `statechart-triple-generation.edn`).
- Keep the chart-driven runtime
  (`orchestrator/src/.../chart_driven.clj`) and the translator
  (`orchestrator/src/.../chart_runtime.clj`).
- Keep both smoke runners
  (`orchestrator/dev/smoke_chart_driven.clj`,
  `orchestrator/dev/smoke_chart_driven_keygen.clj`).
- Keep the conformance tests
  (`orchestrator/test/.../chart_conformance_test.clj`, 10 tests / 50
  assertions). These cover the **documentation** charts and provide
  drift-detection against the procedural runtime; complementary to
  the executable charts.
- Keep the patterns doc (`docs/statechart-best-practices.md`).

**Documentation charts stay where they are.** The charts in
`specs/` were written for human readers and serve that purpose well.
Trying to make a single chart serve both audiences was the lesson
of the first attempt; we don't repeat it.

## What the runtime looks like now

```
specs/executable/
├── statechart-keygen.edn               ← 3-party DKG, real consistency check
└── statechart-triple-generation.edn    ← 2-party Beaver triples

orchestrator/src/.../chart_runtime.clj  ← project-EDN → clj-statecharts spec translator
orchestrator/src/.../chart_driven.clj   ← generic driver + per-ceremony entry points
orchestrator/dev/smoke_chart_driven.clj         ← triple-gen end-to-end smoke
orchestrator/dev/smoke_chart_driven_keygen.clj  ← keygen end-to-end smoke
orchestrator/test/.../chart_conformance_test.clj ← documentation-chart drift detection
docs/statechart-best-practices.md       ← patterns doc (read this before the next chart)
```

## Next ceremonies

The patterns generalize. New ceremonies (sign, presign, reshare-*)
follow the same shape: write the executable chart in
`specs/executable/`, supply a `make-begin` and `build-result`, add
the chart action registry entries needed by ceremony-specific
finalization (the way `keygen-consistency-check` was added). The
generic driver doesn't change.

Order I'd suggest:

1. **Sign** — interesting because the result shape is asymmetric
   (only the coordinator returns a signature). Tests the "results
   may have nil-from-some-parties" path through the consistency
   check.
2. **Presign** — same shape as triple-gen, sanity-check that the
   pattern carries.
3. **Reshare-recovery** — the load-bearing UC2 ceremony. Adds the
   "old vs new participants" wrinkle (only `new_participants` run
   the protocol, but `old_participants` are referenced).
4. **Reshare-refresh / reshare-divorce** — variants of recovery.

Each new ceremony should add a smoke runner that exercises it
end-to-end against real bb wrappers and crypto-core.
