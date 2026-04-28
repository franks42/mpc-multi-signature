# Chart-Driven Runtime POC — Findings

> **Branch:** `feat/chart-runtime-poc`. Not merged. This document
> captures what we learned and the recommended path forward.

## Goal

Test whether the orchestrator's ceremony lifecycle could literally
*execute* the statechart EDN definitions in `specs/`, rather than
just conform to them. If so, drift between chart and code becomes
mechanically impossible — the chart **is** the implementation.

## Outcome — partial success

**What works:**

1. **Translator** (`orchestrator/src/.../chart_runtime.clj`,
   ~250 LOC) reads our project chart EDN — with our project
   conventions (`:statechart/states`, `:statechart/parallel-regions`,
   `:action/X` keywords, `(guard/X args)` lists, `:auto` eventless
   transitions) — and produces a value that
   `clj-statecharts.core/machine` accepts. Three iterations
   surfaced real bugs:
   - `:guards` (vector form) wasn't being resolved into
     clj-statecharts's `:guard` (single predicate).
   - `:auto` was being placed inside `:on` instead of hoisted to
     state-level `:always`.
   - Per-region inner states use plain `:states` (not
     `:statechart/states`); the recursion needed to accept both.

2. **Conformance tests**
   (`orchestrator/test/.../chart_conformance_test.clj`,
   10 tests / 50 assertions, all passing). Each chart driven
   through its expected event sequence with stub action/guard
   registries; reaches the expected terminal state and fires the
   expected actions. Catches drift between chart and procedural
   reality at the structural level — every transition exercised
   by a test cannot diverge silently.

3. **Action/guard registry + chart-driven driver**
   (`orchestrator/src/.../chart_driven_ceremonies.clj`,
   ~400 LOC) implements `run-triple-generation-via-chart` against
   the existing party-connection plumbing.

**What did not work** (under real ceremony execution):

The chart-driven driver, when wired against bb wrappers running
real Noise sessions and crypto-core processes, surfaced multiple
structural mismatches between the *human-readable* chart and what
clj-statecharts requires for *correct execution*. Each fix
exposed the next:

1. **Double-firing of `:action/route-message`.** The chart's
   `:state/running` parent has `:on {:event/protocol-message-emit
   {:target :state/running :actions [:action/route-message]}}`
   AND each region's `:party-state/relaying` has
   `:entry [:action/route-message]`. clj-statecharts (correctly
   per XState semantics) fires both — the parent's transition
   action AND the region's entry action. Result: each protocol
   message routed twice, breaking the recipient's Noise nonce
   sequence on the second decryption attempt with
   `AEADBadTagException`.

2. **Self-loop on parallel parent state conflicts with region
   transitions.** The parent's `:target :state/running` (self-loop
   when receiving `:event/protocol-message-emit` while already in
   `:state/running`) is an *external* transition: clj-statecharts
   exits the parent state and re-enters, which resets each region
   to its initial sub-state. Meanwhile the region's transition
   wants to move from `:awaiting` to `:relaying`. clj-statecharts
   detects the conflicting configuration and asserts:
   `invalid paths: [(:party-state/awaiting) (:party-state/relaying)]`.
   The fix would be either an *internal* transition (no `:target`)
   at the parent level, or removing the parent's `:on` entry
   entirely and letting the regions handle routing.

3. **Notation mismatch between charts and runtime.** Charts use
   namespaced actor keywords (`:actor/holder`,
   `:actor/independent-custodian`); the runtime uses bare role
   keywords (`:holder`, `:ic`). This needed a
   `actor->bare-role` bridge. The "two notational forms" pattern
   is documented in `specs/data-dictionary.edn`; what's not
   documented is that running a chart *executably* requires a
   bridge between them — every keyword that crosses the
   chart/runtime boundary needs translation.

4. **Per-region transient states `:party-state/done` and
   `:party-state/errored`** are defined in the charts but no
   transition ever moves a region into them. Procedural code
   tracks "done" via context, not via region sub-state.
   Functionally these are dead states — they document intent
   but aren't exercised. A chart-driven runtime trips over this:
   the region's `:on` only handles `:event/protocol-message-emit`,
   so no region-level state change happens on
   `:event/ceremony-complete` (which the parent handles).

After three rounds of attempted chart fixes, the smoke runner
reached the point where bb wrappers actually completed
`triple-gen` cryptographically — the route-message double-fire
was eliminated, ceremony_complete events arrived — but the FSM
event loop did not terminate cleanly within the test timeout.
At that point, further iteration would have meant continuing to
debug clj-statecharts execution semantics inside the chart
abstraction, which (per the user's observation that prompted the
stop) is exactly what a chart-first design would have avoided.

## What this confirms

**The user's framing was correct:** *"It's much easier to start the
implementation based on a statechart-machine than to retrofit it
later."*

The existing charts were written by humans, for humans, with
documentation as the primary purpose. They contain idioms that
read naturally as English:

- "Transient `:relaying` state, immediately back to `:awaiting`
  after action."
- "Stay in `:running`, route the message."
- ":party-state/done — terminal substate within :running."

Each of these is structurally subtly wrong as an executable
specification:

- Self-transitions that imply "stay" need to be either *internal*
  (no `:target`) or absent (let the parent handle).
- Eventless transitions in parallel regions need careful state-
  level placement, not nested in `:on`.
- "Terminal substates" not reached by any transition are dead
  decoration that an executor stumbles on.

A chart designed *to be executed* would have caught all of these
at design time because each one would have prevented the very
first run from succeeding. Designed for documentation, they read
fine.

## Recommendation

**Merge the conformance test approach to `main`, not the chart-
driven runtime.** Specifically:

- Keep `chart_runtime.clj` (the translator). Real bugs were
  found and fixed; it works correctly within its scope.
- Keep `chart_conformance_test.clj` (10 tests / 50 assertions).
  This is the meaningful drift-detection foundation. Every chart
  transition exercised by a test cannot drift silently from
  procedural reality. Stage 5c additions can be charted first,
  conformance-tested, then implemented procedurally.
- **Drop `chart_driven_ceremonies.clj`** (the partial runtime).
  Don't carry POC code in `main`. The lessons from it inform
  future chart-design choices but the artifact itself is not
  load-bearing.
- **Don't modify the charts to be execution-correct.** They are
  fine as documentation. If at some future point a chart-first
  redesign is undertaken, it should start fresh — designing
  charts with execution semantics in mind from the beginning,
  rather than retrofitting human-readable charts.

## What a chart-first redesign would look like (if pursued later)

For a future iteration where the chart literally drives the
implementation:

- **No external self-loops on parallel parent states.** Either
  internal transitions (action-only, no `:target`) or events
  handled exclusively by regions.
- **Parallel regions have a real role, not a documentation
  flourish.** Either every region tracks meaningful per-party
  state (and there are real transitions to `:done`/`:errored`)
  or no parallel regions at all (just track per-party state in
  context).
- **One namespace for actor keywords.** Either the chart uses
  bare roles (`:holder`) and the runtime maps them when emitting
  to the wire, OR the chart uses namespaced (`:actor/holder`)
  and the runtime normalizes incoming events. Pick one and
  enforce it.
- **Test the chart end-to-end as a unit before wiring it to
  real plumbing.** A chart that drives a fake-peer simulator
  and reaches `:state/complete` is much easier to debug than
  one that fails opaquely after passing through bb wrappers,
  Noise sessions, crypto-core processes, and back.
- **Chart conformance is a property of the *executable*
  chart**, not a separate exercise. If the chart is the
  implementation, conformance is tautological.

## Files to keep / drop

If merging the conformance tests to `main`:

- ✅ `orchestrator/src/.../chart_runtime.clj` (translator)
- ✅ `orchestrator/test/.../chart_conformance_test.clj` (10 tests)
- ✅ `bb.edn` and `orchestrator/deps.edn` clj-statecharts addition
- ✅ This findings doc
- ❌ `orchestrator/src/.../chart_driven_ceremonies.clj` (drop)
- ❌ `orchestrator/dev/smoke_chart_driven.clj` (drop)
