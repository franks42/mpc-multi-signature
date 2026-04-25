# CLAUDE.md — orientation for Claude Code

Welcome. This file orients you to the `mpc-multi-signature` project.
Read it once at the start of a session, then use the references in
`docs/` and `specs/` as you work.

## TL;DR

This repo will become an exploration harness for a multi-party MPC
wallet recovery system used by the YLDS tokenized-securities product.
The design work is largely done; this is now an implementation
project. The goal of the harness is to validate that the design
composes correctly across separated processes, with an EDN message
vocabulary and a statechart-driven orchestrator as the load-bearing
contract.

There are three layers, top-to-bottom:

1. **Pure Clojure orchestrator** (JVM). Drives ceremonies from a
   REPL, routes EDN messages between parties, enforces timeouts.
2. **Per-party harness** = bb wrapper + Rust subprocess. Three
   instances, one per party (holder, Figure, IC). bb handles EDN ↔
   JSON translation and party-specific business logic; Rust does the
   threshold-signature cryptography.
3. **Cryptographic core** in Rust, wrapping NEAR's
   `threshold-signatures` crate. JSON-Lines stdio interface. Identical
   binary across all three parties; differs only by `--role` flag.

The orchestrator and parties communicate in EDN. The bb wrapper and
Rust binary communicate in JSON-Lines on stdio. The contract between
orchestrator and parties is a two-part artifact: the EDN message
vocabulary plus the ceremony statecharts.

## Authoritative artifacts

These files are the source of truth. When in doubt, they win.

**`specs/data-dictionary.edn`** — every named entity in the system,
with namespaced keyword identifiers, role descriptions, and
cross-references. Read this first.

**`specs/statechart-keygen.edn`**, **`specs/statechart-sign.edn`**,
**`specs/statechart-reshare-recovery.edn`** — orchestrator-side
ceremony lifecycles for the three implemented ceremony types. More
will be added (divorce, refresh, attestation-issuance,
triple-generation, presign).

**`docs/recovery-exploration-harness-design.md`** — architectural
rationale for everything: layer responsibilities, role asymmetry,
implementation plan in stages, EDN vocabulary appendix.

**`docs/mpc-feasibility-spike.md`** — proves cryptographic
feasibility against NEAR's `threshold-signatures` crate with two
working tests. The Rust core's API is exercised here; consult before
writing your own Rust wrapper.

**`docs/ylds-asset-recovery-use-cases.md`** and
**`docs/mpc-kyc-key-recovery.md`** — earlier domain memos. Background
for the problem, not implementation guidance. Skim once for context.

## Things the docs assume you understand

A few load-bearing concepts that matter for implementation choices:

**Bare-form vs namespaced keywords.** The dictionary uses `:actor/*`,
`:state/*`, `:ceremony/*`, `:event/*`, `:crypto/*` namespaced forms
because it catalogs heterogeneous kinds together. Code and wire
messages use bare forms (`:holder`, `:figure`, `:ic`, `:keygen`,
`:commitment-registry`) because context disambiguates. Both forms
denote the same entities.

**The IC is offline by default.** In a 2-of-3 wallet, routine
signing is performed by `{:holder, :figure}` only, with the IC
absent. The IC participates in keygen at wallet creation and in
structural ceremonies (recovery, divorce, refresh) but is offline
otherwise. This is enforced by the cryptographic protocol choice
(OT-based ECDSA, not robust ECDSA) and by the ceremony participant
lists.

**Public key as continuity anchor.** Recovery and divorce ceremonies
preserve the wallet's public key across share-set changes. The
dictionary's `:crypto/wallet-public-key` is the persistent identity
of a wallet; shares are subordinate to it. This is the load-bearing
UC2 invariant.

**The orchestrator is harness-only.** It has no production analog.
In production, a transient "ceremony coordinator" role rotates among
the parties per ceremony. The EDN message vocabulary and statecharts
are designed to span both contexts unchanged; the orchestrator is
where exploration happens.

**Statecharts as specification.** The chart files are the spec for
ceremony lifecycle. Whether the runtime literally executes them via
clj-statecharts or merely conforms to them is a later choice; either
way the chart is authoritative. When the implementation diverges
from the chart, fix the chart or fix the code, not both
independently.

## Implementation plan — staged

The plan is in `docs/recovery-exploration-harness-design.md` under
"Implementation plan". Stages 0 and 0.5 are done (the dictionary and
three statecharts). Your starting point is Stage 1.

A short summary of the staging:

- **Stage 0 (done)** — data dictionary + EDN message vocabulary.
- **Stage 0.5 (in progress)** — orchestrator-side statechart per
  ceremony. Three of eight ceremony charts complete; five remain.
- **Stage 1** — null orchestrator and null parties. Three Clojure
  processes (or three core.async go-blocks in one JVM) exchanging
  EDN messages, with stubbed ceremonies that just round-trip without
  doing real cryptography. Validates routing and message shapes at
  zero cryptographic cost.
- **Stage 2** — replace one party's stub with a real bb-wrapper
  plus Rust binary that performs actual keygen. Other two parties
  stay stubbed. Validates the bb-to-Rust stdio path and the JSON
  translation.
- **Stage 3** — replace the other two parties. End-to-end real
  keygen.
- **Stage 4** — add reshare and sign ceremonies. The high-water
  mark is the executable analog of the UC2 feasibility test:
  end-to-end keygen + reshare-with-member-change + sign across
  separated processes, with public-key preservation verified.
- **Stage 5** — layer business logic: commitment registries,
  attestation services, recovery policy. This is where party-bbs
  start substantively diverging.

Don't skip Stage 1. The temptation will be to jump to Stage 2 because
real crypto is more interesting than stubs. Stage 1 finds half the
ambiguities in the EDN vocabulary at zero cryptographic cost; those
same ambiguities found at Stage 4 cost a day of debugging instead of
half an hour of redesign.

## Implementation hints

A handful of decisions that would otherwise need to be re-derived
each time someone reads the docs.

**Project layout.** Create directories as needed:
```
mpc-multi-signature/
├── docs/                       # design docs (already exists)
├── specs/                      # dictionary + statecharts (already exists)
├── orchestrator/               # JVM Clojure orchestrator
│   ├── deps.edn
│   └── src/...
├── party/                      # bb wrapper used by all three parties
│   ├── bb.edn
│   └── src/...
├── crypto-core/                # Rust binary used by all three parties
│   ├── Cargo.toml
│   └── src/...
└── scripts/                    # convenience shell scripts
```

The same `party/` and `crypto-core/` are used by all three parties;
role differences are configuration, not separate codebases. Don't
fork them per party.

**Dependencies for the orchestrator.** Start minimal: Clojure 1.12,
core.async (or manifold; pick one and stick), `clj-statecharts` (or
the bb-scittle fork), `tools.deps`, an EDN reader (built-in), a
process-spawn library if you need one (java.lang.ProcessBuilder is
fine; doesn't need a wrapper for this scale). Avoid frameworks; this
is a small focused harness.

**Dependencies for the bb wrapper.** Babashka has most of what's
needed in stdlib. EDN reading and writing, JSON via
`cheshire.core`, process spawning via `babashka.process`. No
framework needed.

**Dependencies for the Rust binary.** Look at
`docs/mpc-feasibility-spike.md` Appendix B (the
`ot_offline_custodian.rs` test) for the API surface. Add `serde_json`
for JSON-Lines parsing, `base64` for binary encoding, and one of
`clap` / `argh` / hand-rolled for CLI argument parsing. Pin the
threshold-signatures crate to a specific commit of `near/mpc` for
reproducibility.

**Stdio framing for bb ↔ Rust.** JSON Lines: one JSON object per
line, newline-delimited, no trailing comma. Each message has at
minimum `{"msg_type": ..., "ceremony_id": ...}`. Binary protocol
bodies are base64-encoded strings. The bb wrapper reads from the
Rust subprocess with a line-buffered reader; do not try to use
length-prefixed binary at this stage.

**Share storage.** Plaintext files in a per-party directory:
`./holder/shares/<handle>.bin`, `./figure/shares/<handle>.bin`,
`./ic/shares/<handle>.bin`. Handles are UUIDs generated by the party
when the share is produced. The orchestrator never sees share
contents.

**REPL ergonomics.** The orchestrator's primary interface is the
REPL. Ceremony functions should be blocking from the REPL's
perspective: `(keygen orch [:holder :figure :ic] {:threshold 2})`
returns a result map after the ceremony completes. Internally use
core.async or promises; externally keep the call synchronous. Don't
make REPL users deal with async unless they ask for it.

**Statechart execution.** You have two reasonable choices:

1. *Statechart as documentation only.* Implement the orchestrator's
   ceremony lifecycle as straightforward Clojure code; cite the
   statechart in code comments; periodically run a structural
   conformance check (does the code respect the chart's transitions
   and properties?).

2. *Statechart as runtime structure.* Use `clj-statecharts` (or the
   `franks42/clj-statecharts-bb-scittle` fork) to execute the chart
   directly, with the orchestrator's actions implemented as Clojure
   functions that the chart engine calls.

Option 1 is faster to build and easier to debug. Option 2 makes the
chart genuinely authoritative — the code can't drift from it because
it *is* the code. For Stage 1 either is fine; for Stage 4 and Stage
5, option 2 starts paying off because the failure-handling logic
gets harder to keep correct in handwritten code. **Recommendation:
start with option 1, switch to option 2 when the procedural code
starts feeling tangled.**

**Don't yet build:** persistent state across orchestrator restarts,
multi-ceremony concurrency, real network transport, encryption at
rest, authentication between parties, or anything else listed in
"Out-of-scope concerns" (Appendix C of the architecture doc). The
harness exists to validate cryptographic and structural composition,
not to be a production system.

## Tooling conventions

A handful of non-negotiable conventions for Clojure/bb code in this
repo. Two sibling projects sit alongside this one and serve as the
reference for how to use the shared utilities:

- `../uuidv7.cljc/` — the timestamped-UUID library used for all
  identifiers in this project (ceremony ids, share handles,
  correlation ids).
- `../bb-mcp-server/` — a working bb project that demonstrates how
  trove, uuidv7, bb tasks, and statecharts are wired together.
  Consult this before writing equivalent code from scratch; the
  patterns there are the patterns we want here.

**Always run clj-kondo and cljfmt after every edit.** No exceptions.
Warnings are not acceptable — resolve all of them before reporting an
edit complete. This applies to every Clojure source file the harness
touches (orchestrator `.clj`, party `.bb`/`.clj`, `bb.edn`, `deps.edn`).
A clean lint pass is part of the deliverable; a passing test with
lint warnings is not done.

**Use `../uuidv7.cljc` for all UUIDs.** Every identifier in this
project — ceremony ids, share handles, correlation ids, anything that
would otherwise be a `random-uuid` — uses the v7 timestamped form
from this sibling library. The timestamp prefix is operationally
useful (sortable logs, ordered ceremony histories) and the cost is
zero. Don't reach for `java.util.UUID/randomUUID` or `(random-uuid)`.

**Use trove for instrumentation and logging everywhere.** Both the
orchestrator and the bb wrappers emit structured events through
trove, not `println` or `clojure.tools.logging`. This is a debugging
harness first; structured, queryable events are the deliverable, and
trove's per-ceremony correlation is exactly the shape we need.
`../bb-mcp-server/` shows the patterns — consult it before guessing
at API shape.

**Use bb tasks instead of bash scripts.** Anything that would
otherwise live as `scripts/foo.sh` belongs in `bb.edn` as a `:tasks`
entry. The `scripts/` directory in the project layout above is for
the rare case where bash is genuinely the right answer (and even
then, prefer bb). `../bb-mcp-server/bb.edn` has many examples of the
shape and conventions to use.

## Working style

A few things that will make our collaboration smoother.

**When in doubt, search the specs.** The dictionary entries and
statecharts are designed to answer "what is this entity, what does
it do, what does it interact with." If a question would be answered
by reading those files, read them rather than asking.

**When the spec is silent, ask.** Don't invent. Many design choices
were made deliberately and the spec captures the conclusion, not
the rejected alternatives. If you can't find the answer in the
specs, ask before guessing — the answer is usually simple but
wrong-guess is expensive.

**When the spec contradicts itself, flag it.** It's not finished.
Specifically: the spec is at version 0.1.0 and the dictionary's
status is `:draft`. Inconsistencies between the dictionary and the
statecharts, between the statecharts and the architecture doc, or
between any of those and prior memos exist and are bugs. Surface
them; don't paper over them.

**Test as you go.** Each stage produces a working artifact. Don't
write a full implementation of Stage 1 before any of it runs;
build the smallest piece that exchanges one EDN message
end-to-end, get it working, then add features. The Stage 1 null
orchestrator should be runnable within an hour of starting it.

**Error messages and logs are part of the deliverable.** This is a
debugging tool first; performance comes much later. Spend effort on
clear failure messages that say which actor, which ceremony id,
which event, and what was expected. A failure in Stage 4 that says
"protocol error in figure-bb" is much less useful than "ceremony
abc-123 (reshare-recovery): figure-bb rejected attestation
verification, reason: signature invalid for tas-id kyc-tas-1."

**Honesty over confidence.** If you're unsure whether something
will work, say so before doing it; if it didn't work the way you
expected, say so before claiming success; if you don't understand
why a test passes, that's information worth surfacing. The previous
sessions that produced this design were valuable specifically
because they distinguished "verified" from "expected" from
"assumed." Carry that forward.

## Stage 1 starter task

If you've read this far and want a concrete first task: implement
the Stage 1 null orchestrator and three null party stubs that can
exchange EDN messages for a stubbed `:keygen` ceremony. Acceptance
criteria:

1. Orchestrator binary starts (`clojure -M:run` or equivalent) and
   spawns three party subprocesses.
2. From the REPL: `(keygen orch [:holder :figure :ic] {:threshold 2})`
   sends a `:ceremony/begin-keygen` message to each party.
3. Each party stub responds with a `:ceremony/complete` message
   carrying a placeholder result (e.g., a fake handle UUID and a
   fake public-key string).
4. Orchestrator collects results, runs the keygen consistency
   check from `statechart-keygen.edn` (which will pass trivially
   because all parties returned the same fake public key), and
   transitions to `:state/complete`.
5. The REPL call returns a map with the placeholder handles and
   public key. The whole flow takes well under one second.

No real cryptography. No Rust subprocess yet. No JSON. Just EDN
messages between Clojure processes (or between go-blocks; one JVM
is fine for Stage 1). The point is to validate that the message
shapes round-trip cleanly and the statechart transitions execute
correctly when driven by realistic event sequences. Surprises here
are cheap to fix; surprises at Stage 4 are not.

When that works, the next task is Stage 2: replace the holder stub
with a real bb wrapper plus Rust subprocess that does actual keygen
participation. The other two parties remain stubbed. This validates
the bb-to-Rust stdio path independently of the multi-party
coordination.

Good luck. Ask early, test often.
