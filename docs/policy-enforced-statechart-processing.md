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
| **Peer-on-authorized-path** (came from a peer over an authenticated transport, on a ceremony path the chart has already authorized) | No — sender authority was established at the transport boundary; the ceremony was already gated at start | `:event/protocol-message-emit`, `:event/ceremony-complete` |
| **Boundary** (came from outside the FSM, either with no prior auth, or with auth but requiring semantic authorization) | **Yes** | `:event/begin-ceremony`, `:event/cancel`, an external observer's `:event/objection-raised`, a TAS callback |

Internal and peer-on-authorized-path events don't need new gates;
the work was already done. **Boundary events are where the chart
gains policy structure.**

Note the qualifier on the second row: transport authentication is
not the same as semantic authorization. A TAS callback may be
transport-authenticated (signed by the TAS's registered pubkey)
but still need a chart-layer policy check to confirm "this TAS is
the one designated for this ceremony, and its assertion satisfies
the request." Authentication ≠ authorization.

This dramatically narrows the scope. In the six executable charts
in this project, the only universal boundary event is
`:event/begin-ceremony`. Reshare-flavored ceremonies add a few
more (recovery-intent received from outside, etc.). The chart
doesn't need a gate at every transition — only at the handful of
places where the world talks to the FSM.

## The decision model: four-way, not boolean

Before anything else, **commit to the right vocabulary**. The
two-outcome model — `authorized? true` or `false` — is enough for
a stub but not for the *stable interface*. Once a real PDP exists,
the chart will encounter situations where two outcomes can't
distinguish what's actually happening.

This is well-trodden territory. The XACML standard (OASIS, 2003)
established a four-way decision model that has held up across two
decades of authZ deployments. We adopt three of its categories
and add one async extension:

| Decision | Meaning | XACML lineage |
|---|---|---|
| **`:permit`** | Policy says yes; the requested action is authorized | XACML `Permit` |
| **`:deny`** | Policy says no; this is a *business refusal* (intentional, recorded, auditable) | XACML `Deny` |
| **`:indeterminate`** | Policy applies but couldn't be evaluated — data missing, runtime error, evaluator unavailable | XACML `Indeterminate` |
| **`:deferred`** | Policy answer is pending an external dependency (TAS callback, human approval, etc.). Not a refusal; just "stay tuned" | Not in XACML — XACML assumes synchronous PDP |

(XACML also has `NotApplicable` — "no policy rule covers this
request." We fold this into `:indeterminate` for now: in a
well-configured system every request should have a covering rule,
so `NotApplicable` represents a misconfiguration that the audit
log can disambiguate via the reason keyword. We can promote it to
a first-class category later if it earns its keep.)

**One thing we deliberately don't carry over from XACML: the XML
encoding.** Real XACML deployments paid a heavy operational toll
for the XML-based policy language — verbosity, tooling fragility,
poor authoring ergonomics, mismatch between how policies were
written and how they were debugged. We use EDN throughout: chart
definitions, the request/decision schemas defined below, and
eventually the policy DSL itself. Same decision model, dramatically
better encoding. The lesson from twenty years of XACML deployment
is **the model was right; the syntax was the problem**.

The four-way model matters because the chart needs to *route*
each outcome differently:

- `:permit` → continue the ceremony lifecycle
- `:deny` → terminate the ceremony with `outcome = :rejected`
  (the system worked; it intentionally refused)
- `:indeterminate` → terminate the ceremony with `outcome = :error`
  (the system couldn't decide; this is operations' problem, not
  the requestor's)
- `:deferred` → stay in the gate state; await an eventual
  permit/deny/indeterminate when the external dependency
  resolves

Collapsing `:deny` and `:indeterminate` into a single "failure" is
the trap. They have different operator stories, different audit
stories, and eventually different user-facing stories. Get the
distinction in early; it's expensive to retrofit.

## Trivial PDP from day one

Here's the practical method:

1. **Decide where the gates go** based on boundary-event analysis
   above.
2. **Add gate states to every chart** with the right shape:
   `:state/begin-authorization` (or analogous), routing to the
   four outcomes.
3. **Write a stub PDP** that returns a permit decision for every
   request — but use the full four-way decision shape, not a
   boolean.
4. **Wire the PDP into the gate**: the gate state's `:entry`
   action dispatches the PDP request; the PDP queues a decision
   event corresponding to its answer.

You now have full policy structure visible in the chart. *Every
ceremony passes through a policy gate.* The policy says "permit"
to everything, but the structure is real.

The benefit: when you eventually replace the trivial PDP with a
real one, **the chart doesn't change**. The structure was correct
all along. Only the PDP impl gets richer.

### Anti-anti-pattern: don't let the deny path rot

A pure always-permit stub never exercises the deny path. The
chart's `:event/begin-rejected` transition becomes dormant code
that breaks silently when policy lands and finally tries to use
it. Same for the indeterminate and deferred paths.

Solution: stub PDP with a **mode flag** — `:permit-all` returns
permit, `:deny-all` returns deny, `:always-indeterminate` returns
indeterminate, `:always-deferred` returns deferred (the chart
deadline then fires for the test). All paths are exercised in
tests and smoke runners from day one. When real policy arrives,
every path is already known to work end-to-end.

```clojure
(defn evaluate
  "PDP entry point. Returns a decision conforming to the
   chart-to-PDP contract. mode is one of :permit-all, :deny-all,
   :always-indeterminate, :always-deferred, or eventually a real
   policy reference."
  [mode request]
  (case mode
    :permit-all           {:decision :permit
                           :reason :stub/permit-all}
    :deny-all             {:decision :deny
                           :reason :stub/deny-all}
    :always-indeterminate {:decision :indeterminate
                           :reason :stub/always-indeterminate}
    :always-deferred      {:decision :deferred
                           :reason :stub/always-deferred}))
```

### Audit logging is structural

Every PDP call emits a structured event:

```clojure
{:level :info
 :id    :policy/decision
 :data  {:ceremony :ceremony/keygen
         :decision-point :decision-point/begin-ceremony
         :requestor :party-a
         :decision :permit                      ; or :deny / :indeterminate / :deferred
         :reason :stub/permit-all
         :decision-id #uuid "..."
         :policy-version "0.0.0-stub"
         :decided-at <ts>}}
```

The audit log shape is locked in *before* real policy arrives.
When real PDP rules fire, the log shape doesn't change — only the
`:reason`, `:policy-version`, and supporting fields become more
specific. The day-one decision history (every trivial permit) is
recorded just as durably as the production policy decisions will
be.

## The chart-to-PDP contract

The architecture is "chart owns where, PDP owns what." For that
separation to stay clean operationally — not just philosophically
— the **request and decision schemas must be a first-class
artifact**, defined and committed before either chart or PDP has
much code.

The schemas live in the project's data dictionary alongside
ceremony message types.

### Request shape

```clojure
{:request/id              <uuid>           ; correlation id
 :request/ceremony        :ceremony/keygen
 :request/decision-point  :decision-point/begin-ceremony
 :request/requestor       :party-a
 :request/participants    [:party-a :party-b :party-c]
 :request/threshold       2
 :request/wallet-id       <uuid>           ; or nil for keygen
 :request/handles         {...}            ; opaque references, NOT raw blobs
 :request/evidence-refs   [<ref>...]       ; references into stable storage
 :request/policy-version  "0.0.0-stub"     ; what version PEP expected
 :request/timestamp       <ts>}
```

Two principles to keep this stable:

- **References, not blobs.** The PEP passes evidence *references*
  (handles into a registry); the PDP dereferences as needed. This
  prevents FSM context from turning into a policy cache.
- **Correlation ids matter.** Every request gets a `:request/id`;
  every decision echoes it. This makes async PDP responses
  unambiguous and audit trails straightforward.

### Decision shape

```clojure
{:decision/id              <uuid>           ; matches :request/id
 :decision/decision        :permit          ; or :deny / :indeterminate / :deferred
 :decision/reason          :stub/permit-all
 :decision/explanation     "..."            ; human-readable, optional
 :decision/policy-version  "0.0.0-stub"     ; what version PDP actually used
 :decision/evidence-used   [<ref>...]       ; what the PDP actually consulted
 :decision/decided-at      <ts>}
```

The chart-driven runtime only branches on `:decision/decision`.
The other fields are for audit, debugging, and downstream
consumers. The PDP can grow richer policy-version semantics, more
detailed reasons, and richer evidence-trace fields without the
chart caring.

## What this looks like in chart EDN

Every executable chart gains a `:state/begin-authorization` state
between `:state/pending` and `:state/starting`. The gate routes
the four PDP decisions: permit advances, deny terminates with
`outcome = :rejected`, indeterminate terminates with `outcome =
:error`, deferred holds in the gate (the PDP will queue an
eventual permit/deny/indeterminate when its external dependency
resolves):

```clojure
:state/pending
{:on {:event/begin-ceremony
      {:target  :state/begin-authorization
       :actions [:action/record-handles]}

      :event/cancel
      {:target  :state/failed
       :actions [:action/record-cancel-reason]}}}

:state/begin-authorization
;; :entry dispatches the PDP request. Synchronous PDPs queue the
;; decision event immediately; async PDPs return :deferred and
;; queue a decision later. Either way, the chart waits in this
;; state for one of the three terminal decisions or a deadline.
{:entry [:action/dispatch-begin-policy-evaluation]
 :on   {:event/begin-permitted
        {:target :state/starting}

        :event/begin-denied
        {:target  :state/failed
         :actions [:action/record-policy-rejection]}

        :event/begin-indeterminate
        {:target  :state/failed
         :actions [:action/record-policy-error]}

        :event/cancel
        {:target  :state/failed
         :actions [:action/record-cancel-reason]}

        :event/deadline-elapsed
        ;; Could be deferred-but-never-resolved, or an unresponsive
        ;; PDP. Either way, terminate with :outcome :error.
        {:target  :state/failed
         :actions [:action/record-policy-timeout]}}}

:state/starting
;; ... unchanged from current charts ...
```

The PDP returning `:deferred` is *not* a chart event — the chart
sees it as silence. `:deferred` is a signal *for the audit log*
("PDP accepted the request, working on it") but doesn't trigger
a state transition. The chart simply remains in
`:state/begin-authorization` until a permit/deny/indeterminate
decision arrives or the deadline fires.

### Distinguishing rejected from failed: the outcome payload

`:state/failed` is reachable from multiple paths — a policy deny,
a PDP error, a runtime consistency-check failure, a timeout, an
external cancel. These are different operator stories and
different audit stories, but they all land in the same terminal
state.

To distinguish them without inventing new terminal states, the
ceremony's result payload (delivered to the result-promise on
`:state/failed` entry) carries an explicit `:outcome` keyword:

```clojure
{:outcome :rejected      ; policy intentionally refused (deny)
 :reason  :reason/insufficient-attestation
 :decision-id <uuid>     ; correlation back to the audit log
 ...}

{:outcome :error         ; policy couldn't decide (indeterminate / timeout)
 :reason  :reason/pdp-unavailable
 ...}

{:outcome :aborted       ; runtime ceremony work failed (consistency check, etc.)
 :reason  :reason/public-key-disagreement
 ...}

{:outcome :canceled      ; external :event/cancel
 :reason  ...}
```

Operators triage on `:outcome`. Audit logs filter on `:outcome`.
Future user-facing surfaces explain refusals very differently from
errors. The terminal state is the same; the *meaning* is
distinguished by data.

(A future evolution may promote `:outcome :rejected` to its own
terminal `:state/rejected` if the operational distinction proves
worth a chart-shape change. Until then, the structured payload
keeps the semantic distinction without disrupting the existing
result-delivery plumbing.)

### A structural property: gate cannot be bypassed

A conformance test should assert that **`:state/starting` is
unreachable from `:state/pending` except via `:state/begin-authorization`**.
This guarantees that no future chart edit accidentally restores
the implicit-trust path. The test walks every transition out of
`:state/pending` and verifies its target is the gate (or a
terminal state, for cancels).

For ceremonies that change the wallet's structure (a recovery, a
divorce, a periodic refresh), an additional
`:state/authorization-gate` state appears later in the lifecycle
where two or more parties each independently evaluate the
request. Same four-way decision shape, different policy question,
parallel PDP calls. The same structural property applies: the
ceremony's working states must be unreachable except through that
gate.

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
Peer events arriving on an *already-authorized* ceremony path go
through Noise transport with identity verification. That is
sufficient: the ceremony was gated at start, and the transport
binds the message to a registered participant. New policy at the
chart layer would be redundant. **But:** events that arrive
transport-authenticated yet require fresh semantic authorization
(a TAS callback, an external observer's objection) *do* need a
chart-layer gate. Authentication ≠ authorization.

**"What if the PDP needs to fire async (e.g., wait for a TAS to
respond)?"** That's exactly what `:deferred` is for. The PDP
returns `:deferred` to signal "request accepted, working on it";
the chart simply waits in the gate state. The PDP eventually
queues a permit/deny/indeterminate decision when its external
dependency resolves. The gate state has a deadline that fires if
no decision ever arrives. See also [best-practices pattern #10][bp10]
on transient wait states.

**"Why permit/deny/indeterminate/deferred and not just true/false?"**
Because two outcomes can't distinguish "the system worked and
intentionally refused" from "the system couldn't decide." The
former is a business event the requestor should hear about; the
latter is an operations problem the requestor shouldn't be
blamed for. The XACML standard reached this conclusion in 2003
and it's held up since. We adopt three of XACML's categories
(Permit, Deny, Indeterminate) plus one async extension (Deferred)
that XACML itself doesn't model.

[bp10]: ./statechart-best-practices.md

## Summary

- Every external event entering an FSM is a policy decision —
  whether you wrote a PDP or not.
- "Policy as orthogonal" risks drift and invisible decisions.
- "Policy as chart guards" risks unreadable charts and brittle
  evolution.
- The compositional middle: **chart owns *where* decisions are
  made; PDP owns *what* they say**.
- The decision vocabulary is **four-way**, not boolean: permit /
  deny / indeterminate / deferred. Three come from XACML; deferred
  is the async extension.
- The chart routes the four decisions distinctly: permit advances,
  deny terminates with `:outcome :rejected`, indeterminate
  terminates with `:outcome :error`, deferred holds the gate state
  awaiting an eventual answer.
- Rejected and failed share a terminal state but differ in the
  result payload's `:outcome` keyword. Operators triage on
  `:outcome`; audits filter on it.
- A trivial PDP from day one (with mode flags exercising every
  decision path) makes the structure visible without committing
  to policy content.
- The chart-to-PDP contract — request and decision schemas — is a
  first-class artifact, defined before either side has much code.
- Audit logging is structural: every decision is recorded the
  same way, before and after real policy lands.
- A structural property — *the gate cannot be bypassed* — is
  asserted in conformance tests so future chart edits can't
  accidentally restore implicit-trust paths.
- The chart's stable shape is the architectural payoff: real
  policy can grow over time without reshaping the lifecycle.

This pattern is general, not specific to this project. Any
chart-driven system that interacts with the world will benefit
from naming its boundary-event policy decisions as states, even
before the policy itself is real.
