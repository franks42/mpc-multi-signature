# Review: Policy-Enforced Statechart Processing

## Scope

This review covers the proposed next-stage design in:

- `docs/policy-enforced-statechart-processing.md`
- `docs/statechart-best-practices.md`
- `specs/executable/statechart-sign.edn`

The goal here is not to re-argue whether policy should exist. The doc already gets the main architectural move right: the question is how to integrate policy decisions into the chart-driven runtime without either hiding them outside the chart or polluting the chart with policy content.

## Overall Assessment

The document's central claim is sound: **the chart should own where policy decisions happen, and a separate PDP should own what those decisions say**.

That is the right middle path between two bad designs:

- policy entirely outside the chart, where it drifts and becomes invisible
- policy embedded directly in chart guards, where lifecycle structure gets buried under authorization logic

The strongest parts of the proposal are:

1. **Boundary-event narrowing.** The policy doc correctly distinguishes boundary events from internal and transport-authenticated events. This keeps policy structure focused on real ingress points rather than spreading gates everywhere.
2. **Trivial PDP first.** Adding the gate shape before real policy content exists is exactly the right staging move for this project.
3. **Deny-path discipline.** The `:permit-all` / `:deny-all` stub mode is important. It prevents the rejection path from rotting before real policy lands.
4. **Structural audit logging.** If policy is structural, decision logging should also be structural from day one.
5. **Stable chart shape.** The claim that the chart shape should land once and survive PDP evolution is the main architectural payoff.

## What I Agree With Strongly

### 1. The chart is the right PEP

Treating the chart as the policy enforcement skeleton is a good fit for this project.

The chart already owns:

- lifecycle sequencing
- terminal-state semantics
- timeout and abort behavior
- external event ingress

Those are exactly the places where policy enforcement belongs structurally. A separate PDP can stay pure and declarative, but the chart is still where the system should visibly pause, ask, and branch.

### 2. Boundary-event analysis is the right scoping tool

The distinction between:

- internal events
- transport-authenticated peer events
- boundary events from outside the FSM

is the cleanest part of the design.

This keeps policy integration limited to the places where the world talks to the FSM. That is crucial, because otherwise policy starts smearing across the whole chart vocabulary and becomes hard to reason about.

### 3. The phasing is realistic

The staging sequence in the doc is good engineering discipline.

In particular, landing:

- the gate state
- the PDP request/decision callout
- the logging shape
- both allow and deny transitions

before any real authorization rules exist is the right order.

That lets Stage 5c validate the structural integration before it takes on attestation semantics, registries, or asynchronous waits.

## Main Suggestions

### 1. Use more than pass / reject in the decision model from the start

The doc's examples mostly use a two-outcome model:

- `:event/begin-authorized`
- `:event/begin-rejected`

That is enough for a stub. It is not enough for the stable interface.

At minimum, the chart/PDP contract should distinguish:

- **permit**: authorized business outcome
- **deny**: unauthorized business outcome
- **indeterminate**: policy could not reach an answer
- **deferred**: answer is pending an external dependency

Why this matters:

- a deny is not an infrastructure failure
- a PDP timeout is not the same as a policy refusal
- a waiting-on-TAS case should not be represented as either a deny or a failed chart

If these categories are collapsed too early, the chart shape will likely have to change later, which is exactly what the proposal is trying to avoid.

### 2. Separate rejected from failed in the chart vocabulary

This is the biggest concrete chart-level recommendation I would make.

Right now the proposed examples route `:event/begin-rejected` to `:state/failed`. I would avoid that if possible.

Reason:

- **rejected** means the system worked and intentionally refused
- **failed** means the system could not complete because something broke

Those are different operator stories, different audit stories, and eventually different user-facing stories.

If the runtime can support it, I would prefer a distinct final state such as:

- `:state/rejected`

with a structured failure/result shape that clearly marks it as a business denial, not a runtime failure.

If the runtime cannot yet distinguish terminal outcomes beyond `:state/complete` and `:state/failed`, then at least make the result payload explicit enough that "rejected" is not hidden inside generic failure handling.

### 3. Make the chart-to-PDP contract a first-class artifact

The design is conceptually strong, but it wants one more explicit artifact: a stable request/decision schema.

I would define that early, before implementation spreads.

The request should likely include fields like:

- ceremony kind
- action or decision point name
- initiator / requestor
- participants
- threshold
- relevant handles or wallet identifiers
- evidence references, not raw evidence blobs when possible
- policy-data revision identifiers
- correlation id / decision id

The decision should likely include:

- decision kind (`:permit`, `:deny`, `:indeterminate`, `:deferred`)
- reason keyword
- human-readable explanation if useful
- decision id
- evaluated policy version
- references to the evidence actually consulted

Without this, the chart/PDP boundary may stay philosophically clean but become operationally vague.

### 4. Be careful with the statement that transport-authenticated events need no chart-layer policy

This is mostly correct in the current MPC ceremony model, but it should be stated more narrowly.

The safe version is:

> peer-originated events that arrive through an already-authorized ceremony path and whose sender authority is established by the transport boundary do not need an additional chart-layer policy gate.

That leaves room for future event types where authentication is necessary but not sufficient.

For example, an authenticated TAS callback or observer objection may still need semantic authorization at the chart boundary.

### 5. Treat asynchronous policy as a first-class case, not an extension case

The doc already points in the right direction by referencing pattern #10 from `docs/statechart-best-practices.md`.

I would go one step further: even if the first PDP implementation is synchronous, define the contract and chart vocabulary so async policy is not a retrofit.

That means having a model where a gate can eventually say:

- decision arrived and permit
- decision arrived and deny
- still waiting
- timed out
- evaluator unavailable

You do not need all those states in the first scaffolding patch, but the interface should leave room for them.

## Concrete Example: How I Would Integrate Policy into the Sign Ceremony

I would use the sign ceremony as the reference example.

Why sign is the best demonstration case:

1. Its executable chart already notes that the documentation chart had a policy-check state and the executable chart may grow that gate later.
2. It exercises a realistic policy question that is easier to explain than recovery: issuer policy, coordinator policy, spending policy, or transaction-approval policy.
3. It is simpler than reshare, so the policy integration can be shown without immediately mixing in multi-party gate aggregation.

### Current shape

Today, the executable sign chart effectively does this:

```clojure
:state/pending
{:on {:event/begin-ceremony
      {:target  :state/starting
       :actions [:action/record-handles]}

      :event/cancel
      {:target  :state/failed
       :actions [:action/record-cancel-reason]}}}
```

That means `:event/begin-ceremony` is still implicitly trusted.

### Suggested scaffolded shape

I would change the ceremony shape conceptually to this:

```clojure
:state/pending
{:on {:event/begin-ceremony
      {:target  :state/begin-authorization
       :actions [:action/record-handles
                 :action/record-begin-request]}

      :event/cancel
      {:target  :state/failed
       :actions [:action/record-cancel-reason]}}}

:state/begin-authorization
{:entry [:action/dispatch-begin-policy-evaluation]
 :on    {:event/begin-authorized
         {:target :state/starting}

         :event/begin-rejected
         {:target  :state/rejected
          :actions [:action/record-policy-rejection]}

         :event/begin-policy-indeterminate
         {:target  :state/failed
          :actions [:action/record-policy-error]}

         :event/begin-policy-deferred
         {:target :state/awaiting-begin-policy}

         :event/cancel
         {:target  :state/failed
          :actions [:action/record-cancel-reason]}

         :event/deadline-elapsed
         {:target  :state/failed
          :actions [:action/record-timeout]}}}

:state/awaiting-begin-policy
{:on {:event/begin-authorized
      {:target :state/starting}

      :event/begin-rejected
      {:target  :state/rejected
       :actions [:action/record-policy-rejection]}

      :event/deadline-elapsed
      {:target  :state/failed
       :actions [:action/record-policy-timeout]}

      :event/cancel
      {:target  :state/failed
       :actions [:action/record-cancel-reason]}}}

:state/starting
;; unchanged from today's chart
```

### Why this shape works

This is not about adding complexity for its own sake. It separates three things that want to stay separate:

1. **Business refusal**
   The transaction was intentionally not authorized.

2. **Infrastructure failure**
   The policy subsystem could not decide, timed out, or errored.

3. **Deferred external wait**
   The chart is alive and blocked on an external answer.

Those distinctions map directly to operator needs and audit semantics.

### What the stub PDP should do for sign first

For the first implementation stage, I would still keep the PDP trivial.

For example:

- `:permit-all` => queue `:event/begin-authorized`
- `:deny-all` => queue `:event/begin-rejected`

But I would define the decision schema so the same gate can later evaluate real sign-policy inputs like:

- who requested the sign
- transaction digest classification
- allowed coordinator
- issuer policy requirements
- address policy constraints
- wallet-specific restrictions

### What I would not do yet

I would not put issuer-policy logic in chart guards.

I would also not try to model all downstream sign-policy semantics in the first patch. The first patch should only establish:

- the explicit gate state
- the PDP dispatch action
- the decision event vocabulary
- the logging shape
- both allow and deny path coverage

That is enough to make policy structural.

## Suggested Implementation Principles for This Stage

If you move forward with this design, I would suggest holding the implementation to these rules:

1. **Every new policy gate must name the policy question explicitly.**
   `:state/begin-authorization` is fine for a universal start gate. Later gates should be equally explicit about what is being decided.

2. **Decision events should describe outcomes, not policy internals.**
   The chart should branch on permit/deny/deferred/indeterminate, not on attestation-format details.

3. **PDP requests should carry references to evidence, not arbitrarily large evidence payloads, unless the first phase truly needs inline data.**
   This keeps FSM context from turning into a policy cache.

4. **Audit log schema should be fixed early.**
   The reason taxonomy can grow later, but the log envelope should stabilize early.

5. **Smoke runners should exercise both allow and deny from day one.**
   Otherwise the negative path will drift.

## Bottom Line

This is a strong architectural direction.

The document has the right main idea: policy should be structurally visible in the chart, but policy content should still live outside the chart in a separate evaluator.

The main things I would tighten before implementation are:

1. define a richer stable decision model than pass / reject
2. distinguish rejected from failed in chart semantics
3. make the chart-to-PDP contract an explicit artifact
4. design for asynchronous policy responses from the start, even if the first PDP stays synchronous

If you do those four things, this next stage should fit well with the chart-driven runtime you already have, instead of becoming a special-case policy subsystem hanging awkwardly off the side.