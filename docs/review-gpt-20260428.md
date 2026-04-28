# Review: Chart-Driven Runtime for mpc-multi-signature

## Scope

This review focuses on the chart-driven orchestrator runtime the project explicitly flagged for review:

- [read-before-review.md](read-before-review.md)
- [docs/statechart-best-practices.md](docs/statechart-best-practices.md)
- [docs/chart-runtime-poc-findings.md](docs/chart-runtime-poc-findings.md)
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_runtime.clj](orchestrator/src/mpc_multi_signature/orchestrator/chart_runtime.clj#L224)
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L395)
- [specs/executable/statechart-keygen.edn](specs/executable/statechart-keygen.edn#L104)
- [orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj](orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L1)

This is a review of the design and implementation shape. I did not run the smoke runners or tests as part of this review.

## Findings

### 1. The current conformance tests validate the wrong artifact

The runtime now executes the executable charts under `specs/executable/`, but the conformance tests still load the documentation charts under `specs/` and describe themselves as checking alignment with the procedural implementation.

Evidence:

- [orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L2](orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L2) says the tests build each ceremony chart from `specs/`.
- [orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L5](orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L5) still references the procedural implementation.
- [orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L78](orchestrator/test/mpc_multi_signature/orchestrator/chart_conformance_test.clj#L78) explicitly loads `../specs/statechart-...` rather than `../specs/executable/statechart-...`.
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L395](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L395) is the actual runtime entry point, and it builds the live machine from executable charts.

Why this matters:

The documentation charts are now intentionally non-executable references. That makes them useful documentation, but weak runtime protection. The current tests protect the story the project tells about the system, not the artifact the runtime actually executes.

Recommendation:

Refocus automated conformance checks around `specs/executable/`. Keep documentation-chart checks if they still serve a docs QA purpose, but stop treating them as the primary runtime safety net. The highest-value executable-chart assertions are:

- every non-final state handles `:event/cancel`
- deadline and error paths exist where expected
- finalization gates cannot be bypassed
- every action/guard symbol referenced by an executable chart resolves in the runtime registries
- ceremony-specific invariants such as keygen agreement and reshare public-key continuity remain represented in the chart

### 2. The effect model is workable but fragile because it is split across `fsm/assign` and mutable pending-event queues

The runtime works, but the mechanism is easy to use incorrectly. Context updates depend on remembering `fsm/assign`, while follow-on control flow depends on mutating `::pending-events` and draining that queue after transitions.

Evidence:

- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L32](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L32) explicitly documents the `fsm/assign` gotcha.
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L100](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L100) and [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L173](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L173) show actions that both mutate queue state and update FSM context.
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L349](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L349) implements the synthetic-event drain loop.
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L413](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L413) injects the mutable queue into the live FSM context.

Why this matters:

This is fine for a disciplined small codebase, but Stage 5c will add more ceremony-specific business logic, more authorization gates, and more policy-specific transitions. At that point, the hidden contract becomes the risk:

- forget `fsm/assign` and the state update silently disappears
- queue a synthetic event in the wrong place and control flow becomes harder to reason about
- combine side effects and context mutation in one action and debugging gets more subtle

Recommendation:

Short term, add a small wrapper or macro for context-updating actions so the `fsm/assign` requirement becomes structural rather than mnemonic. Longer term, consider formalizing an effect model where actions return state changes and commands separately instead of depending on ad hoc queue mutation.

### 3. The dual-chart model is an explicit tradeoff, but it also creates durable documentation debt

The project made the correct local decision to stop executing the documentation charts and build execution-correct variants under `specs/executable/`. That solved real runtime problems. It also created a permanent two-source model.

Evidence:

- [docs/chart-runtime-poc-findings.md](docs/chart-runtime-poc-findings.md) explains why the original documentation charts failed as executable artifacts.
- [docs/statechart-best-practices.md](docs/statechart-best-practices.md) codifies the execution-correct patterns that the executable charts follow.
- [specs/executable/statechart-keygen.edn#L1](specs/executable/statechart-keygen.edn#L1) explicitly labels itself the executable variant and points back to the documentation chart.

Why this matters:

The current split is understandable, but it means the project has accepted two truths:

- one truth for humans
- one truth for the machine

That can be managed, but only if the team treats it as an ongoing maintenance cost rather than a solved problem. The more Stage 5c adds branching policy workflows, the more expensive that duplication becomes.

Recommendation:

If both chart families remain, define their responsibilities narrowly:

- `specs/executable/` is the runtime contract
- `specs/` is explanatory material and must not carry stronger correctness claims than that

Then add explicit review checks for drift between them where it matters, especially event vocabulary, terminal states, and ceremony phases.

### 4. Transport concerns still leak into the chart boundary

One of the most important lessons in the best-practices doc is also one of the main architectural smells: transport-handshake traffic and ceremony-protocol traffic share the same statechart-facing event path.

Evidence:

- [docs/statechart-best-practices.md](docs/statechart-best-practices.md) pattern 4b explains that even ceremonies with no peer-to-peer crypto still need `:event/protocol-message-emit` handlers because Noise handshake traffic arrives the same way.
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L321](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L321) maps protocol messages directly into FSM events.
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L48](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L48) centralizes relay logic, which is good, but still keeps the FSM boundary transport-aware.

Why this matters:

This is not a bug in the harness. It is, however, an abstraction leak. The chart should ideally model ceremony lifecycle, not handshake necessities of the carrier layer. As Stage 5c adds more policy-oriented ceremonies, this kind of coupling will become less intuitive to future contributors.

Recommendation:

Keep the current design for now if it is stable, but document this as a boundary compromise, not just a pattern. If future refactoring budget appears, the cleanest move is to terminate transport-level handshakes below the chart boundary so the FSM only sees ceremony-semantic traffic.

## What Looks Strong

### 1. The separation of translator, runtime, and ceremony chart is good

The split is crisp:

- [orchestrator/src/mpc_multi_signature/orchestrator/chart_runtime.clj#L224](orchestrator/src/mpc_multi_signature/orchestrator/chart_runtime.clj#L224) is a focused translator from project EDN conventions to `clj-statecharts`
- [orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L395](orchestrator/src/mpc_multi_signature/orchestrator/chart_driven.clj#L395) is the generic driver and action/guard host
- executable charts carry ceremony-specific lifecycle shape

That is the right decomposition for a harness that expects to add more ceremonies.

### 2. The runtime is disciplined about ceremony-specific behavior living at the edges

The `make-begin` and `build-result` closures are a good compromise. They keep the generic runtime generic while allowing ceremony-specific request and result shapes. I would not rush to replace these with a more abstract registry until the number of ceremonies materially increases.

### 3. The use of `::` plumbing keys is idiomatic and appropriate

The distinction between `:ceremony/*` domain context and `::...` runtime plumbing is clean. I would keep that. A record or dynamic-var approach would make the system heavier without solving the real complexity.

### 4. The project learned from the failed first attempt instead of hiding it

The combination of [docs/chart-runtime-poc-findings.md](docs/chart-runtime-poc-findings.md) and [docs/statechart-best-practices.md](docs/statechart-best-practices.md) is unusually valuable. The project is not just documenting the final pattern set; it is documenting the traps that forced those patterns into existence. That will pay off when new ceremonies are added.

## Recommendations

### 1. Retarget conformance tests to executable charts first

This is the most important follow-up. If there is only one structural improvement to make before Stage 5c, make it this one.

### 2. Add a wrapper for context-updating actions

A `defaction` or `defassign-action` style wrapper would reduce the highest-cost local footgun without changing the overall runtime model.

### 3. Genericize obviously generic action names

Aliases like `:action/triple-shape-check` and `:action/presig-shape-check` are defensible, but they read like ceremony-specific logic even when they are not. For actions that are genuinely ceremony-agnostic, the chart vocabulary should say so directly.

### 4. Add one more pattern before Stage 5c: transient wait states versus terminal aborts

The current pattern language is strong for threshold-MPC ceremonies. Stage 5c will introduce policy and attestation workflows, which are more likely to need pauses, objections, retries, and asynchronous approvals. The patterns doc should make explicit when a workflow should enter a waiting state rather than collapsing into `:state/aborting`.

### 5. Treat the dual-chart model as an ongoing maintenance obligation

The project has already made the decision. The mistake now would be pretending there is no carrying cost. Put that cost in the process explicitly.

## If I Were Starting From Scratch

These are not recommendations to rewrite the project now. They are the architectural choices I would make differently if starting greenfield with the lessons this implementation has already surfaced.

### 1. I would push much harder for a single chart source of truth

I would try to avoid a permanent split between documentation charts and executable charts. If I needed rich visual charts for humans, I would prefer generating one representation from the other or constraining the visual language so the human-readable artifact could still be mechanically trustworthy.

### 2. I would separate state transitions from side effects from day one

The current model works, but I would prefer actions to yield explicit commands rather than mutating a pending-event queue from inside state-transition logic. A more explicit effect model would make ceremony logic easier to review and reduce reliance on tool-specific behavior like `fsm/assign`.

### 3. I would consider an MPC-specific layer above raw statecharts

The ceremonies share a recurring structure: start, scatter messages, gather completions, validate invariants, finalize. A thin domain layer for MPC rounds could reduce repetition while still compiling to ordinary statecharts underneath.

### 4. I would make executable-chart validation a first-class artifact earlier

From scratch, I would decide much earlier that runtime-facing tests must target the runtime-facing charts. Documentation checks are still useful, but they would never be the main structural validation layer.

### 5. I would try to isolate transport mechanics below the ceremony FSM boundary

The current harness learned to live with transport handshake traffic crossing the same event boundary as ceremony traffic. Greenfield, I would try to avoid that because it obscures the mental model of what the chart is supposed to mean.

## Bottom Line

This is a good architectural step forward. The chart-driven runtime is materially better than the deleted procedural runtime because it centralizes lifecycle behavior in one model and makes ceremony structure much easier to inspect.

The main remaining risks are not that the approach is wrong. They are that the current supporting systems still lag behind the new architecture:

- tests still center the documentation artifact rather than the executed one
- the effect model depends on local discipline in a few places where the framework offers little protection
- the split between human and executable charts is now a real maintenance burden, not a temporary transition artifact

If those edges are handled deliberately, the current foundation looks strong enough to carry Stage 5c.