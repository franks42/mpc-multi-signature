# Architectural Review: Chart-Driven Runtime for mpc-multi-signature

**Reviewer:** Gemini 3.1 Pro (Preview)
**Focus:** `v0.7.0-all-ceremonies-chart-driven` (Chart-Driven Runtime POC to Main)
**Context:** Migration from procedural `ceremony.clj` to statechart-driven execution via `clj-statecharts`.

## Executive Summary

The architectural shift to a chart-driven runtime is a massive improvement for managing distributed multi-party computation lifecycles. By unifying the protocol definition (the chart) and the execution, drift is eliminated. The patterns extracted (`docs/statechart-best-practices.md`) show a deep understanding of standard FSM pitfalls versus operational reality.

The separation of concerns is clean:
1.  **Translator** (`chart_runtime.clj`): Pure data transformation shielding the engine from project-specific EDN idioms.
2.  **Driver** (`chart_driven.clj`): Generic event loop and standardized action injection.
3.  **Executables** (`specs/executable/*.edn`): Domain-specific lifecycles.

## Targeted Feedback (Addressing `read-before-review.md` Questions)

### 1. Action-Registry Abstraction & Aliasing
**Observation:** Aliasing specific keywords like `:action/triple-shape-check` and `:action/presig-shape-check` to the same `check-results-collected` function creates safe isolation but adds indirection and registry bloat.
**Recommendation:** Genericize the keywords in the charts to reflect the *behavior* rather than the *ceremony*. Using an action named `:action/verify-all-parties-responded` or `:action/check-results-collected` directly in the EDN chart makes the statechart more self-explanatory to an external reader and reduces the mapping overhead in `chart_driven.clj`.

### 2. The `fsm/assign` Trap (Pattern #1)
**Observation:** Relying on developer memory to wrap context updates in `fsm/assign` is fragile, especially leading into Stage 5c, which will introduce many custom policy checks.
**Recommendation:** Create a macro (e.g., `defaction` or `defupdater`).
```clojure
(defmacro defupdater [name args & body]
  `(def ~name
     (statecharts.core/assign
       (fn ~args ~@body))))
```
This forces the correct schema at declaration time and visually distinguishes context-updating fns from side-effect-only fns.

### 3. Plumbing Context (`::keys`)
**Observation:** Using double-colon namespacing (`::orch`, `::pending-events`) to separate runtime plumbing from domain data (`:ceremony/*`) is highly idiomatic in Clojure.
**Recommendation:** Keep this pattern. It avoids wrapping the state in a heavy record or relying on dynamic variables (`binding`), maintaining the purity and testability of the FSM transition functions.

### 4. Data-Driven Per-Ceremony Entry Points
**Observation:** The thin entry points (`run-keygen-via-chart`, etc.) currently map `make-begin` and `build-result`.
**Recommendation:** Not strictly necessary to refactor right now. The functional wrappers are clean and type-safe. However, if Stage 5c adds 10+ new TAS/policy ceremonies, moving to a registry-driven approach (e.g., `(run-ceremony orch :keygen options)`) where the ceremony specs are just maps of `{ :chart-path ... :make-begin-fn ... :build-result-fn ... }` would reduce boilerplate.

### 5. Conformance Tests
**Observation:** The documentation charts and executable charts have intentionally diverged. Testing the documentation charts checks pedagogical consistency but provides zero runtime safety guarantees.
**Recommendation:** Refocus the conformance tests. They should verify that the *executable charts* comprehensively cover the vocabulary defined in `specs/data-dictionary.edn`. Specifically, assert that for every ceremony, the executable chart handles `:event/cancel`, `:event/ceremony-error`, and `:event/deadline-elapsed` (as required by property checks).

### 6. The 9 Patterns
**Observation:** The patterns are solid. Pattern #4b (Transport vs. Crypto separation) is vital.
**Potential Missing Pattern for 5c:** **"Transient Failures vs. Terminal Aborts"**. Right now, most error states transition straight to `:state/aborting`. As business logic (Stage 5c) is added (e.g., waiting for an external TAS approval), you may encounter transient failures where a retry or wait state is more appropriate than an immediate abort. You should establish a pattern for "Wait-and-Retry" vs "Fast-Fail".

### 7. Anti-patterns
**Observation:** The documented anti-patterns hit all the right notes for `clj-statecharts`.
**Addition:** Add "Silent failure of pending events" to the anti-patterns list. Since synthetic events are queued to `::pending-events` and drained sequentially, an error inside the event loop drainage could leave pending events unhandled. Documenting how unhandled synthetic events surface in logs will save debugging time later.

## "Start from Scratch" Recommendations

If rebuilding this system from scratch today, armed with the knowledge of what caused friction (e.g., the `fsm/assign` gotcha, dual-chart maintenance, transport-vs-crypto routing), I would advocate for the following architectural shifts:

### 1. Reject "Dual Charts" and Demand a Single Source of Truth
Maintaining `specs/` (documentation charts) and `specs/executable/` (runtime charts) is a massive long-term risk and guarantees eventual drift.
**Recommendation:** Use a visual, standards-based statechart editor (e.g., Stately/XState) to draw the charts, export them as standard SCXML or JSON, and parse *that* directly into the Clojure runtime. If a visual construct (like a parallel region) breaks execution, either fix the engine to handle it or restrict the visualization syntax. The visual chart must *be* the executable code.

### 2. Purify the Action Architecture 
Relying on mutable atoms (`::pending-events`) and developer discipline to wrap context updates in `fsm/assign` mixes side-effects with state transitions, creating fragility.
**Recommendation:** Adopt a strict **Command Pattern (or Elm Architecture)**. Action functions should be 100% pure. Instead of mutating state directly or swapping atoms, an action should take a `state` and `event` and return a tuple: `[new-context, [list-of-commands]]` (e.g., `[new-ctx, [:cmd/send-msg msg :cmd/queue-event :event/finalization-passed]]`). The FSM runner evaluates this naturally without wrappers or atoms, eliminating the `fsm/assign` trap entirely.

### 3. Build an MPC-Specific "Scatter-Gather" Abstraction Over Statecharts
General-purpose statecharts are powerful, but MPC ceremonies have a very specific, repetitive shape: *Broadcast -> Wait for N/M peers -> Validate -> Next Round*.
**Recommendation:** Rather than wiring generic `:on` transitions and `guards/all-parties-done` for every single round, build an "MPC Round" abstraction macro. It would compile down to the statechart but would natively understand "Wait for Threshold" or "Wait for All". A 150-line statechart could be expressed in 20 lines of domain-specific configuration.

### 4. Collapse the Babashka <-> Rust Bridge (Process Consolidation)
A pure JVM orchestrator talking to a Babashka wrapper talking to a Rust binary via JSON-Lines over `stdio` means every new domain concept must be mapped across EDN -> JSON -> Serde.
**Recommendation:** Eliminate the Babashka middleman layer as a separate process. Compile the Rust `crypto-core` with JNI bindings (via the `jni` crate) or as a native shared library (JNA/FFI), and invoke it directly from the JVM or Babashka process. Consolidating the participant node into a single process eliminates brittle stdio parsing and massively simplifies structured logging.

### 5. Transport Layer Independence in the Chart
The discovery that Noise_KK handshake bytes trigger the FSM `:event/protocol-message-emit` (Pattern #4b) breaks abstraction. The chart shouldn't need to know if the transport layer requires handshakes.
**Recommendation:** Intercept the Noise_KK handshake entirely within the network/transport boundary of the orchestrator *before* it ever touches the FSM. The FSM should truly *only* deal with cryptographic payload messages.

## Final Note for Stage 5c
The chart-driven foundation is highly robust. To ensure it survives Stage 5c gracefully, prioritize wrapping the FSM context assignment and shifting the testing focus to executable properties. The FSM is now the source of truth—protect its edges.