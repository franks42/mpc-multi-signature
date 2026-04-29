# Policy-enforced statechart processing

> Why every state transition from outside the FSM is a policy
> decision — even before you have a policy engine — and how to make
> those decisions structurally visible.

This doc captures an architectural insight that surfaced during the
chart-driven runtime work and shapes how Stage 5c business logic
will be added. The short version:

**Statecharts already make policy decisions.** When you fire an
event into an FSM, *something* decided that event was authorized.
If you didn't write a Policy Decision Point, you wrote one
implicitly — by allowing the call site to fire the event with no
check.

The orchestrator REPL firing `(orch/keygen ...)` is making a policy
decision: "this requestor is authorized to start a keygen ceremony."
There's no PDP yet, so the decision is implicit (always yes), but
it's a decision nonetheless.

The thesis of this document: **make implicit policy decisions
explicit, in the chart, before you have real policy.** That way
the chart shape lands once. Real policy fills in over time without
reshaping the chart.

## The implicit-decision insight

Most people, when they first see a chart-driven runtime, think of
events as just data. An event arrives, the FSM transitions, work
happens. Where's the policy? "Policy is somewhere else — in a
separate engine, alongside the chart."

That framing is too clean. It hides what's actually happening.

Consider the simplest thing the orchestrator does: a user types
`(orch/keygen o [:holder :figure :ic] {:threshold 2})` at the REPL.
The orchestrator fires `:event/begin-ceremony` into the FSM. The
chart transitions from `:state/pending` to `:state/starting`. The
ceremony begins.

Five questions were answered by something:

1. *Who* is allowed to start a keygen ceremony? (Anyone with REPL
   access, currently.)
2. *Which parties* are allowed to participate? (The three named in
   the call.)
3. *With what threshold?* (Whatever the caller asked for.)
4. *Right now?* (Yes — no rate-limiting, no approval window.)
5. *In this organizational/legal context?* (Whatever the harness
   is configured for.)

Every one of those questions has an answer. The orchestrator made
those decisions. They just don't appear anywhere in the chart, the
runtime, or the audit log. They are **implicit**.

When Stage 5c lands a real KYC TAS, an address policy registry, an
attestation freshness window, the answers to those five questions
become explicit and verifiable. **But the questions themselves
were always there.** Stage 5c isn't *adding* policy; it's making
the policy that already exists *visible*.

## Two failure modes

When engineers first try to add policy to a chart-driven system,
they tend to fall into one of two traps.

### Failure mode 1: "policy is orthogonal"

Treat policy as a completely separate subsystem that runs
alongside the chart. The chart says what transitions are
*possible*; a separate guard layer says whether a given party is
*allowed*.

What goes wrong:

- **Drift.** The chart changes (new event type), the policy layer
  doesn't get updated. The new event slips through unguarded.
- **Invisible decisions.** You look at the chart to understand
  the protocol; you have to look elsewhere to understand who can
  do what. Reasoning about the system requires holding two
  documents in your head simultaneously.
- **Duplicate vocabulary.** The chart names states; the policy
  layer names actors. They drift apart, and the same concept gets
  spelled three different ways.

This is the failure mode most projects land in by default, because
it feels modular. It is not.

### Failure mode 2: "policy is in chart guards"

Embed policy directly into the chart. Every transition's
`:guards` list contains a predicate that evaluates the policy.
The chart is now the single source of truth.

What goes wrong:

- **Charts become unreadable.** Lifecycle structure (the dance) is
  buried under policy logic (the rules). You can't see the
  ceremony shape anymore.
- **Policy can't evolve independently.** A new TAS gets added,
  every reshare-flavored chart needs editing. Address policy
  changes require chart redeploys.
- **The chart EDN gets ugly.** Predicate logic in EDN is awkward;
  rich policy data has to be pulled into FSM context, blowing it
  up.

This is the failure mode the cleanroom designer falls into,
because it feels pure. It is not.

## The compositional middle: chart as enforcement skeleton

The standard separation, demystified for people who haven't seen
XACML:

| Role | What it does | In this project |
|---|---|---|
| **PEP** (Policy Enforcement Point) | Knows *when* a decision is needed, *intercepts* the action, *enforces* the result. | The chart. Names the decision points as states; names the outcomes as events. |
| **PDP** (Policy Decision Point) | Knows *what* the decision should be, given the inputs. | A separate evaluator (eventually `stroopwafel`-driven). Stateless function: request in, decision out. |
| **PIP** (Policy Information Point) | Knows the *data* the decision depends on. | Registries: address policy, commitments, attestation cache. |

The chart and the PDP are **co-designed at their interface**:
both know about `:event/figure-gate-pass`. They're loosely coupled
in their internals: the chart doesn't know what attestation types
exist; the PDP doesn't know what state machine it's gating.

You don't pick "chart or PDP." You pick **what each owns**:

- The chart owns *protocol structure*. Where decisions happen.
  What outcomes lead where. The lifecycle dance.
- The PDP owns *policy content*. What credentials count. What
  freshness applies. What rules combine.

When you draw it this way, the question "should policy be in the
chart?" becomes "should the chart name decision points?" — and the
answer is obviously yes. The question "should the chart contain
policy logic?" becomes a different question with a different
answer — no.

## Where decisions actually need to be marked

The first refinement: not every state transition is a policy
decision. Look at where events come *from*:

| Event source | Policy decision? | Example |
|---|---|---|
| **Internal** (queued by an action) | No — the action that queued it already encoded the rule | `:event/finalization-passed` after consistency check passes |
| **Transport-authenticated** (came from a peer over Noise + identity verification) | No — auth was checked at the transport boundary | `:event/protocol-message-emit`, `:event/ceremony-complete` |
| **Boundary** (came from outside the FSM with no prior auth) | **Yes** | `:event/begin-ceremony`, `:event/cancel`, `:event/recovery-intent-received` |

Internal and transport-authenticated events don't need new gates;
the work was already done. **Boundary events are where the chart
gains policy structure.**

This dramatically narrows the scope. In the six executable charts
in this project, the only universal boundary event is
`:event/begin-ceremony`. Reshare-flavored ceremonies add a few
more (recovery-intent received from outside, etc.). The chart
doesn't need a gate at every transition — only at the handful of
places where the world talks to the FSM.

## Trivial PDP from day one

Here's the practical method:

1. **Decide where the gates go** based on boundary-event analysis
   above.
2. **Add gate states to every chart** with the right shape:
   `:state/begin-authorization` (or analogous) with two outgoing
   events: `:event/begin-authorized` (proceed) and
   `:event/begin-rejected` (abort).
3. **Write a stub PDP** that returns a permissive answer for every
   request.
4. **Wire the PDP into the gate**: the gate state's `:entry`
   action dispatches the PDP request; the PDP queues the
   appropriate result event.

You now have full policy structure visible in the chart. *Every
ceremony passes through a policy gate.* The policy says "yes" to
everything, but the structure is real.

The benefit: when you eventually replace the trivial PDP with a
real one, **the chart doesn't change**. The structure was correct
all along. Only the PDP impl gets richer.

### Anti-anti-pattern: don't let the deny path rot

A pure always-yes stub never exercises the deny path. The
chart's `:event/begin-rejected` transition becomes dormant code
that breaks silently when policy lands and finally tries to use
it.

Solution: stub PDP with a **mode flag** — `:permit-all` returns
yes, `:deny-all` returns no. Both paths are exercised in tests
and smoke runners from day one. When real policy arrives, both
paths are already known to work end-to-end.

```clojure
(defn evaluate
  "PDP entry point. mode is one of :permit-all, :deny-all, or
   eventually a real policy reference."
  [mode request]
  (case mode
    :permit-all {:authorized? true  :reason :stub/permit-all}
    :deny-all   {:authorized? false :reason :stub/deny-all}))
```

### Audit logging is structural

Every PDP call emits a structured event:

```clojure
{:level :info
 :id    :mpc.policy/decision
 :data  {:ceremony :ceremony/keygen
         :action :action/begin-ceremony
         :requestor :holder
         :authorized? true
         :reason :stub/permit-all
         :decided-at <ts>}}
```

The audit log shape is locked in *before* real policy arrives.
When real PDP rules fire, the log shape doesn't change — only the
`:reason` becomes more specific. The day-one decision history
(every "trivial yes") is recorded just as durably as the
production policy decisions will be.

## What this looks like in chart EDN

Every executable chart gains a `:state/begin-authorization` state
between `:state/pending` and `:state/starting`:

```clojure
:state/pending
{:on {:event/begin-ceremony
      {:target  :state/begin-authorization
       :actions [:action/record-handles]}

      :event/cancel
      {:target  :state/failed
       :actions [:action/record-cancel-reason]}}}

:state/begin-authorization
;; The :entry action calls the PDP synchronously. Result is
;; queued as a synthetic event, drained by the runtime, fires
;; the appropriate transition.
{:entry [:action/dispatch-begin-policy-evaluation]
 :on   {:event/begin-authorized
        {:target :state/starting}

        :event/begin-rejected
        {:target  :state/failed
         :actions [:action/record-policy-rejection]}

        :event/cancel
        {:target  :state/failed
         :actions [:action/record-cancel-reason]}}}

:state/starting
;; ... unchanged from current charts ...
```

For reshare-flavored ceremonies, an additional
`:state/authorization-gate` state appears later in the lifecycle
where Figure and IC each independently evaluate the recovery /
divorce / refresh request. Same pattern, different policy
question, two parallel PDP calls.

## How this maps to the project's Stage 5c

The 5c plan reflects this thinking. The chart-shape work lands
*first*, with trivial PDP, before any real policy logic exists:

- **5c.0a** — PDP infrastructure + universal `:state/begin-authorization` gate. Every executable chart gains the gate. PDP is trivial. **The chart shape lands here.**
- **5c.0b** — Foundational-principle compliance (IC independence, KYC TAS as separate principal). PDP gains access to address-policy data; rules still trivial.
- **5c.1** — Commitment registries (real persistent state).
- **5c.2** — Attestation services. PDP starts checking attestation signatures — first real policy evaluation.
- **5c.3** — Multi-party authorization gates for reshare-flavored ceremonies. Real `stroopwafel`-driven policy DSL replaces parts of the trivial PDP.
- **5c.4** — Objection-window infrastructure (first ceremony with a real wait state).
- **5c.5** — End-to-end UC2: the first ceremony the harness can REFUSE based on policy.

The crucial property: **chart shape doesn't change after 5c.0a.**
Each subsequent substage either adds new charts (5c.1, 5c.2) or
adds *new* states to *existing* charts (5c.3, 5c.4) — but the
universal `:state/begin-authorization` gate stays put, and the
trivial PDP gradually becomes a real one without changing where
it's called from.

## Common confusions, addressed

**"If the trivial PDP just says yes, why bother?"** Because the
*structure* says no something is forbidden, even when the *content*
says yes everything is allowed. When you replace the content, the
structure doesn't have to change. Without the structure, you'd
be retrofitting policy into running ceremonies, which is the hard
problem.

**"Aren't we just adding overhead?"** A trivial PDP call is a
function call returning a constant. The cost is one extra state
transition per ceremony. For a ceremony that takes seconds and
involves real cryptography, this is unmeasurable.

**"Why not just check policy at the call site (in the REPL or
client)?"** Because the call site changes per environment (REPL,
production coordinator, automated test). Pulling the policy
decision into the chart means it's checked the same way regardless
of who fired the event.

**"Doesn't this break the orthogonality argument?"** No, because
"chart owns *where* decisions are made" is *not* "chart owns *what*
decisions say." The PDP impl is still its own subsystem with its
own concerns; it's just *called from* the chart at well-defined
points. The orthogonality is between *structure* and *content*,
not between *chart* and *policy*.

**"What about events from peers — don't those need policy too?"**
Peer events go through Noise transport with identity verification.
That *is* a policy check — just at the transport layer. The chart
trusts peer-authenticated events for the same reason a TLS-backed
HTTP server trusts authenticated requests: the boundary already
checked. New policy at the chart layer would be redundant for these
events.

**"What if the PDP needs to fire async (e.g., wait for a TAS to
respond)?"** Then the gate state has a real wait shape: deadline
events, retry events, abort events. This is exactly what
[best-practices pattern #10][bp10] is about. The chart represents
the wait explicitly; it's not a hidden side effect inside an
action.

[bp10]: ./statechart-best-practices.md

## Summary

- Every external event entering an FSM is a policy decision —
  whether you wrote a PDP or not.
- "Policy as orthogonal" risks drift and invisible decisions.
- "Policy as chart guards" risks unreadable charts and brittle
  evolution.
- The compositional middle: **chart owns *where* decisions are
  made; PDP owns *what* they say**.
- A trivial PDP from day one makes the structure visible without
  committing to policy content. Mode flag (permit-all vs deny-all)
  exercises both paths from the start.
- Audit logging is structural: every decision is recorded the
  same way, before and after real policy lands.
- The chart's stable shape is the architectural payoff: real
  policy can grow over time without reshaping the lifecycle.

This pattern is general, not specific to this project. Any
chart-driven system that interacts with the world will benefit
from naming its boundary-event policy decisions as states, even
before the policy itself is real.
