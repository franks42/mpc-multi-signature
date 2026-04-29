# Policy-enforced statechart processing

> Why every state transition from outside the FSM is a policy
> decision — even before you have a policy engine — and how to make
> those decisions structurally visible.

## The scenario

Imagine a system where multiple parties cooperatively perform
sensitive operations on shared cryptographic state. An MPC wallet,
say, where key generation, signing, and share rotation are all
coordinated multi-party protocols. Each protocol is a *ceremony*:
a defined lifecycle of message exchanges between parties, modeled
as a statechart so the dance is explicit, auditable, and
mechanically verifiable.

Some ceremonies should require authorization to start. Recovering
a lost share, for instance, must verify the requestor's identity
before any cryptographic work happens — otherwise an attacker can
hijack a wallet by claiming "I lost my share." Other ceremonies
may need lighter checks (routine signing) or none (background
key-refresh). Either way, **somewhere a decision is being made
about who can do what, when, under what conditions.**

The question this doc addresses: where does that decision belong?
In a separate policy subsystem orthogonal to the chart? In the
chart's transition guards? Somewhere else? And what do you do
*before* you've built the real policy engine — does the work just
not happen, or is there an interim approach that surfaces the
decisions structurally with very little code?

The thesis: **make implicit policy decisions explicit, in the
chart, before you have real policy.** That way the chart shape
lands once. Real policy fills in over time without reshaping the
chart.

## The implicit-decision insight

Most people, when they first see a chart-driven runtime, think of
events as just data. An event arrives, the FSM transitions, work
happens. Where's the policy? "Policy is somewhere else — in a
separate engine, alongside the chart."

That framing is too clean. It hides what's actually happening.

Consider the simplest thing such an orchestrator does: a user
types something like `(begin-keygen orch [:party-a :party-b :party-c]
{:threshold 2})` at a REPL. The orchestrator fires
`:event/begin-ceremony` into the FSM. The chart transitions from
`:state/pending` to `:state/starting`. The ceremony begins.

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

When the system eventually grows a real attestation service, an
address-policy registry, an attestation freshness window, the
answers to those five questions become explicit and verifiable.
**But the questions themselves were always there.** Adding policy
isn't *creating* policy; it's making the policy that already
exists *visible*.

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
| **PDP** (Policy Decision Point) | Knows *what* the decision should be, given the inputs. | A separate evaluator (a declarative policy engine, e.g. Datalog-based). Stateless function: request in, decision out. |
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

For ceremonies that change the wallet's structure (a recovery, a
divorce, a periodic refresh), an additional
`:state/authorization-gate` state appears later in the lifecycle
where two or more parties each independently evaluate the
request. Same pattern, different policy question, parallel PDP
calls.

## Phasing the work

The work decomposes naturally into phases. The chart-shape work
lands *first*, with trivial PDP, before any real policy logic
exists. Each subsequent phase preserves the chart shape and
either enriches the PDP or adds adjacent capabilities.

1. **Scaffolding.** PDP infrastructure (with permit-all / deny-all
   modes) plus a universal `:state/begin-authorization` gate added
   to every executable chart. The PDP is trivial; every ceremony
   still proceeds. **The chart shape lands here.**

2. **Trust-root compliance.** External principals (KYC trust
   attestation services, custodian operators) become first-class
   actors with their own pubkeys registered in policy data. The
   PDP starts to *consult* this data, even if its rules remain
   trivial.

3. **Persistent registries.** Address policies, commitment
   ledgers, attestation caches — long-lived state outside the
   per-ceremony FSM. The PDP can now query stable data across
   ceremonies.

4. **Attestation services as ceremonies.** Issuing an attestation
   is itself a (single-party) ceremony. The PDP starts validating
   attestation signatures — *first non-trivial policy evaluation*.

5. **Multi-party authorization gates.** Reshare-flavored ceremonies
   (recovery, refresh, divorce) gain `:state/authorization-gate`
   states where two or more parties independently evaluate the
   request. Real declarative policy rules (e.g., a Datalog DSL)
   replace parts of the trivial PDP.

6. **Wait-state infrastructure.** Time-bounded windows where
   external observers can object to a pending structural change.
   First ceremony with a real wait state; introduces durable
   cross-restart state.

7. **End-to-end policy-gated recovery.** All pieces wired
   together: the first ceremony the system can REFUSE based on
   policy, with the refusal reason recorded structurally in the
   audit log.

The crucial property: **chart shape doesn't change after the
scaffolding phase.** Each subsequent phase either adds *new*
charts or adds *new* states to *existing* charts, but the
universal `:state/begin-authorization` gate stays put, and the
trivial PDP gradually becomes a real one without changing where
it's called from.

Practitioners using this pattern in their own systems would
adapt the specifics (which actor types, which attestation
shapes, which wait-state semantics) but the **phasing principle**
generalizes: chart-shape first, policy content gradually.

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
