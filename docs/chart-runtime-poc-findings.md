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

Six ceremonies (every threshold-MPC ceremony in the project) now
drive end-to-end through the chart-driven runtime: keygen,
triple-generation, presign, sign, reshare (covering recovery,
refresh, divorce variants), and share-possession-proof. Each has a
per-ceremony smoke runner under `orchestrator/dev/`. All exercise
real Noise_KK sessions + crypto-core; final signatures cross-verify
against the wallet pubkey. After the cleanup commit that redirected
`orchestrator.core`'s public API to chart-driven entry points, the
procedural `ceremony.clj` was deleted entirely.

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

## What was merged

The `feat/chart-runtime-poc` branch became the foundation for all
ceremony work. After the migration was complete, the procedural
`ceremony.clj` was deleted and `orchestrator.core`'s public API was
redirected to call the chart-driven entry points. The conformance
tests still cover the **documentation** charts in `specs/` (which
remain as human-readable references) — they provide drift-detection
between the documentation chart shapes and the executable chart
shapes; they have nothing to compare against the procedural runtime
because the procedural runtime is gone.

## What the runtime looks like now

```
specs/executable/                       ← six charts, one per ceremony
├── statechart-keygen.edn               ← 3-party DKG, real consistency check
├── statechart-triple-generation.edn    ← 2-party Beaver triples
├── statechart-presign.edn              ← 2-party presignature
├── statechart-share-possession-proof.edn ← variable participants, binding-mode option
├── statechart-sign.edn                 ← asymmetric result (only coordinator signs)
└── statechart-reshare.edn              ← covers recovery, refresh, divorce

orchestrator/src/.../chart_runtime.clj  ← project-EDN → clj-statecharts spec translator
orchestrator/src/.../chart_driven.clj   ← generic driver + per-ceremony entry points
orchestrator/dev/smoke_chart_driven*.clj         ← six per-ceremony smoke runners
orchestrator/test/.../chart_conformance_test.clj ← documentation-chart drift detection
docs/statechart-best-practices.md       ← patterns doc (read this before the next chart)
```

The `orchestrator/src/.../ceremony.clj` (procedural runtime) is
gone — the chart-driven runtime fully subsumed it.

## Next ceremonies

The patterns generalize. New ceremonies (Stage 5c business logic:
attestation-issuance, etc.) follow the same shape: write the
executable chart in `specs/executable/`, supply a `make-begin`
and `build-result`, add
the chart action registry entries needed by ceremony-specific
finalization (the way `keygen-consistency-check` was added). The
generic driver doesn't change.

Each new ceremony should add a smoke runner under
`orchestrator/dev/smoke_chart_driven_<name>.clj` that exercises it
end-to-end against real bb wrappers and crypto-core, with a final
cross-verification step where applicable.
