# Statechart best practices (clj-statecharts, this project)

Working notes from the chart-runtime POC. These patterns are what
made the executable triple-generation chart drive a real ceremony
end-to-end (real Noise sessions, real crypto-core, real
cross-verification). The companion artifacts that demonstrate every
pattern in working code:

- Chart: `specs/executable/statechart-triple-generation.edn`
- Driver: `orchestrator/src/.../chart_driven.clj`
- Translator: `orchestrator/src/.../chart_runtime.clj`
- Smoke: `orchestrator/dev/smoke_chart_driven.clj`

When you write a new executable ceremony chart, work through this
checklist. When something is wrong it usually means one of these
patterns was violated.

## 1. `fsm/assign` for every context update

This is the gotcha that costs hours. clj-statecharts only applies
context changes from actions whose return value is a
`ContextAssignment` record. Plain return values from actions are
**silently discarded**.

```clojure
;; WRONG — return value is ignored, context not updated
(defn record-party-done
  [state {:keys [from result]}]
  (assoc-in state [:ceremony/per-party-state from] :party-state/done))

;; RIGHT — fsm/assign wraps the function so its return becomes
;; ContextAssignment, which clj-statecharts recognizes and applies
(def record-party-done
  (fsm/assign
   (fn [state {:keys [from result]}]
     (-> state
         (assoc-in [:ceremony/per-party-state from] :party-state/done)
         (assoc-in [:ceremony/results from] result)))))
```

Pure side-effect actions (sending messages, queueing events,
delivering to a promise) don't need `fsm/assign` — they return state
unchanged. But anything that *reads-and-modifies* context must use it.

**Side effects and `fsm/assign` compose.** The function wrapped by
`fsm/assign` can do side effects before returning the updated state.
The keygen consistency check is the canonical example: it queues a
synthetic event AND updates context in one action.

```clojure
(def keygen-consistency-check
  (fsm/assign
   (fn [{:keys [::pending-events :ceremony/results] :as state} _event]
     (let [pks (->> results vals (map :result/public-key-hex) (into #{}))]
       (cond
         (= 1 (count pks))
         (do (swap! pending-events conj :event/finalization-passed)
             (-> state
                 (assoc :ceremony/public-key (first pks))
                 (assoc :ceremony/verification-shares ...)))
         :else
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/public-key-disagreement)))))))
```

Source of truth: `clj-statecharts-bb-scittle/src/statecharts/impl.cljc`
lines 161–169 (`execute` reduces actions; only `ContextAssignment`
return values become the new state).

## 2. Internal transitions for in-state events

Events that should *not* exit the current state get **no `:target`**:

```clojure
:state/running
{:on {:event/protocol-message-emit
      {:actions [:action/route-message]}}}  ; no :target → internal
```

Confirmed by clj-statecharts source: nil-target transitions skip
entry/exit actions and parallel-region resets. This is what you want
for "while in :state/running, route messages, but don't re-enter
:state/running."

The alternative — `:target :state/running` — is an *external*
self-loop, which exits and re-enters the state. Side effects:
parallel regions reset to their initial substate, entry actions
re-fire, exit actions fire on the way out. Almost never what you
want.

## 3. Vector-of-guarded transitions for fork-on-state branches

When the next transition depends on context (e.g. "stay if more
parties are still pending; advance if this is the last one"), use a
vector of transitions evaluated in order:

```clojure
:event/ceremony-complete
[{:actions [:action/record-party-done]
  :guards  [(guard/at-least-one-party-still-running)]}     ; internal
 {:target  :state/finalizing
  :actions [:action/record-party-done]
  :guards  [(guard/all-parties-done-after-this-event)]}]
```

The first matching guard wins. Note the guards reason about state
*before* the action runs, so use arithmetic on the inflight event
(`(< (inc k) n)` not `(< k n)`).

Translator note: this project's translator collapses
`:guards [(form)]` into clj-statecharts's `:guard <pred>`. Multiple
guard forms are AND-ed.

## 4. No parallel regions unless they have real transitions

The first attempt's documentation chart had per-party regions like:

```clojure
:region/holder
{:initial :party-state/awaiting
 :states  {:party-state/awaiting {...}
           :party-state/relaying {...}
           :party-state/done     {}    ; ← never reached
           :party-state/errored  {}}}  ; ← never reached
```

Per-party state lived in `:ceremony/per-party-state` context anyway,
so the regions were dead structure. Worse, they caused double-firing
of `:action/route-message` (parent's `:on` AND each region's `:entry`
both fired) and resets when the parent's external self-loop fired.

Rule: **parallel regions only when each region has at least one
transition that does meaningful work**. If the regions are
documentation flourish, drop them and track per-party state in
context.

## 4b. Transport-layer messages count as `:event/protocol-message-emit`

Even ceremonies with no peer-to-peer crypto-protocol exchange (e.g.
share-possession-proof, where each party computes its proof locally)
still need an `:event/protocol-message-emit` handler in
`:state/starting` and `:state/running`. **Reason:** the bb wrapper
establishes pairwise Noise_KK sessions before computing crypto, and
the handshake bytes flow through the orchestrator as
`:protocol/private` messages — which the driver translates to
`:event/protocol-message-emit` events. If the chart drops these
handlers, handshake messages hit the FSM with no transition, get
silently dropped, and the bb wrappers time out waiting on each
other.

The chart can't tell "crypto bytes" from "Noise handshake bytes"
apart at the orchestrator layer — they're the same EDN message
type. So:

```clojure
:state/starting
{:on {:event/protocol-message-emit
      {:target :state/running :actions [:action/route-message]}
      ;; (other handlers...)}}

:state/running
{:on {:event/protocol-message-emit
      {:actions [:action/route-message]}    ; internal — see pattern #2
      ;; (other handlers...)}}
```

Even if you "know" the ceremony has no protocol exchange. The
transport-layer routing is invisible from the chart's perspective.

## 5. Synthetic events via a pending-events queue

When an action's purpose is to compute a result that triggers the
next transition (e.g. "consistency check passes → finalize"), the
action can't directly fire an event in clj-statecharts. The pattern:

```clojure
(defn- triple-shape-check
  [{:keys [::pending-events :ceremony/results] :as state} _event]
  (swap! pending-events conj
         (if (every-result-ok? results)
           :event/finalization-passed
           :event/finalization-failed))
  state)
```

The driver's event loop drains `pending-events` after every external
transition (see `transition-and-drain!` and `drain-pending-events!`
in chart_driven). Events in the queue fire one at a time until the
FSM is terminal or the queue is empty.

This is how `:state/finalizing`'s entry action queues the result
event that drives the next transition.

## 6. One keyword namespace at the chart/runtime boundary

Pick `:holder` (bare) OR `:actor/holder` (namespaced) and use it
everywhere — chart, runtime registries, peer messages, context. The
documentation charts in `specs/` use `:actor/*`; the runtime
everywhere else uses bare. Mixing them needs a translation bridge,
which is dead weight and a source of bugs.

The executable charts in `specs/executable/` use bare keywords — same
as the rest of the project.

## 7. Plumbing context vs domain context

Context fields fall into two camps. Keep them visually distinct:

- **Domain context** uses `:ceremony/*` namespaced keys.
  `:ceremony/id`, `:ceremony/per-party-state`, etc. These show up in
  chart definitions and serialize cleanly.
- **Plumbing context** uses double-colon keyword namespacing
  (`::orch`, `::result-promise`, `::pending-events`,
  `::participants`). These are runtime handles the actions need;
  they never appear in the chart EDN.

Initial context at `fsm/initialize` time merges both. clj-statecharts
threads the merged map; actions destructure whichever fields they
need.

## 8. Ceremony-specific shape via plumbing-context functions

Different ceremonies need different begin-message shapes and
different success-result shapes. Don't write a separate driver
per ceremony — keep the chart-driven driver generic and inject the
ceremony-specific behavior as functions in plumbing context.

The two hooks that matter in practice:

- `::make-begin` — `(fn [me] -> begin-msg-edn)` — used by
  `:action/send-begin-to-all-participants` to build the per-role
  begin message. Triple-gen produces `:ceremony/begin-triples`,
  keygen produces `:ceremony/begin-keygen`, etc.
- `::build-result` — `(fn [state] -> result-map)` — used by
  `:action/notify-coordinator-success` to build the success shape
  the result-promise receives. Triple-gen returns
  `{:triple-handle ... :handles ... :ceremony/id ...}`; keygen
  returns `{:public-key ... :share-handle ... :verification-shares
  ... :ceremony/id ...}`.

The chart actions stay generic and reusable across ceremonies. The
entry-point function for each ceremony (e.g. `run-keygen-via-chart`)
is a thin wrapper that supplies these two functions plus the
ceremony's chart path and domain context.

```clojure
(defn run-keygen-via-chart [orch participants opts]
  (let [...]
    (run-chart-fsm! orch participants chart-path
                    domain-ctx make-begin build-result deadline-ms)))
```

This keeps the action registry shared between ceremonies; only the
chart and the entry-point's wiring vary.

## 9. Initial entry to a state runs all entry actions in order

`:state/starting`'s `:entry` actions fire when entering. With
`:event/begin-ceremony` driving `:pending → :starting`, the entry
actions (`send-begin-to-all-participants`, `start-deadline-timer`)
both run before the FSM settles. This is the right place for
ceremony-startup side effects.

## Anti-patterns we hit

| Anti-pattern | Symptom | Fix |
|---|---|---|
| Forgot `fsm/assign` on a context-updating action | Context never updates; FSM stuck on guards | Wrap in `fsm/assign` |
| `:target :state/running` self-loop on parallel parent | Regions reset on every event; `AEADBadTagException` from Noise nonce desync | Internal transition (no `:target`) |
| `:auto :next-state` nested inside `:on` | clj-statecharts ignores it (it expects `:always` at state level) | Translator hoists it; or write `:always` directly |
| Region states `:done`/`:errored` never reached | Dead structure; chart parses but documents lies | Either give them real transitions or remove the regions |
| Action checks for a result field the wrapper doesn't send | `:event/finalization-failed` fires unexpectedly | Read what bb actually returns; don't assume |
| Dropped `:event/protocol-message-emit` handler "because the ceremony has no protocol exchange" | bb wrappers time out during Noise handshake; "EOF during Noise handshake" thrown | Keep the handler — Noise handshake bytes still flow as `:protocol/private` (pattern #4b) |

## Working examples

Two ceremonies are working under the chart-driven driver. The
patterns generalize: keygen worked on the first attempt, no debugging
rounds, once the patterns from triple-gen were applied.

- `specs/executable/statechart-triple-generation.edn` (2 parties,
  no orchestrator-side consistency check)
  - Smoke: `orchestrator/dev/smoke_chart_driven.clj` — keygen
    (procedural) → chart-driven triple-gen → presign → sign →
    cross-verify
- `specs/executable/statechart-keygen.edn` (3 parties, real
  consistency check at finalization)
  - Smoke: `orchestrator/dev/smoke_chart_driven_keygen.clj` —
    chart-driven keygen → procedural triple-gen → presign → sign →
    cross-verify against the chart-driven keygen pubkey
- `specs/executable/statechart-presign.edn` (2 parties, no check;
  pattern carried first-attempt)
  - Smoke: `orchestrator/dev/smoke_chart_driven_presign.clj`
- `specs/executable/statechart-share-possession-proof.edn` (variable
  participant set, no peer-to-peer crypto, binding-mode option)
  - Smoke: `orchestrator/dev/smoke_chart_driven_share_proof.clj` —
    plain mode + binding mode, both cryptographically verified

Driver: `orchestrator/src/.../chart_driven.clj`. The action
registry is shared across all ceremonies; per-ceremony differences
live in the entry-point function (`make-begin` and `build-result`).
