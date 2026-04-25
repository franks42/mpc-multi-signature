# YLDS MPC Cryptographic Feasibility: Spike Report

## Background

The YLDS asset-recovery design (`ylds-asset-recovery-use-cases.md`)
describes a multi-party MPC wallet scheme with three share-holders:
the holder, Figure, and an Independent Custodian (IC). Two structural
properties of this scheme need to hold for the design to work:

1. **Routine signing must be possible with the IC offline.** Routine
   transactions are signed by holder + Figure as a 2-party subset of
   a 2-of-3 wallet, with the IC dormant. The IC is held in reserve
   for ceremonies that change the wallet's structure (recovery,
   divorce, refresh).

2. **Resharing with member change must preserve the public key.**
   When the holder loses their share, the wallet can be recovered by
   resharing across {Figure, IC, new_holder} without changing the
   on-chain address. This is the load-bearing claim for Use Case 2
   in the recovery design.

Both properties are claimed by various MPC libraries in their
documentation. This report describes a hands-on verification of both
properties against a specific candidate library and the architectural
implications that flow from the verification.

The first property is the more constraining one: it eliminates entire
classes of MPC schemes from consideration. The structure of this
report reflects that priority.

## The operational requirement constrains the cryptographic choice

A 2-of-3 MPC wallet whose three share-holders must all be online for
every signing operation is operationally unviable. Three reasons:

- **Operational fragility.** Every transaction depends on every
  party's availability. The IC's downtime becomes wallet downtime.
  A service that exists to provide *backup* trust is paradoxically a
  single point of failure for routine signing.

- **Attack surface.** A party with a long-lived online MPC share
  participating in every signing operation is a high-value,
  always-reachable target. By contrast, a party whose share is offline
  99.9% of the time and only comes online for rare structural
  ceremonies presents a much smaller attack surface.

- **Cost-benefit misalignment.** The IC adds value during rare events
  (recovery, divorce, refresh) but would do operational work for
  every transaction if it were on the routine-signing path. The
  reserved-custodian model aligns the operational profile with the
  value profile.

Threshold-signature schemes vary in whether they support this offline-
party model at routine-signing time. The relevant property is whether
*any* subset of size ≥ t can complete the signing pipeline (offline
phase, presign, sign), without the other parties being involved in
*any* phase. Some schemes provide this; others impose participant-
count constraints at the offline or presign phase that conflict with
it.

This narrows the field of candidate libraries dramatically. Schemes
based on the GG18/GG20/CGGMP family generally provide the property.
Schemes that bundle their offline phase with extra robustness
guarantees often do not, because the robustness comes from requiring
participation by parties beyond the signing threshold.

## Library selection and dependency analysis

After surveying the available open-source threshold-signature
libraries, the candidate selected for the spike was the
`threshold-signatures` crate from NEAR's MPC project, located at
`github.com/near/mpc/crates/threshold-signatures`. Selection criteria:

- Audited (the crate's predecessor at `near/threshold-signatures`
  underwent professional audit prior to PR#15; the audited version is
  the basis of the current code).
- Provides two distinct ECDSA variants — robust and OT-based — with
  the OT-based variant explicitly supporting different participant
  sets and thresholds for each phase of the signing pipeline. This is
  the property the operational model requires.
- Explicit support for member-changing resharing in the README:
  *"Key Resharing / Key Refresh: allows parties to reshare their
  keys, add new members, or remove existing ones."*
- secp256k1 ECDSA (the curve used on Provenance Blockchain).
- MIT-licensed.
- Actively maintained (latest release Feb 2026; contributors with
  established credibility in the field, including Chelsea Komlo of
  FROST).

The competing candidates were each ruled out for specific reasons:
LFDT-Lockness `cggmp24` is excellent but its current version
explicitly does not yet support key refresh ("This crate does not
(currently) support: Key refresh..."), with paper-faithful
implementation planned which would constrain refresh to same-
participant-set rotation. Silence Labs' `dkls23` is audited and
production-grade but its public API surface suggests same-participant-
set rotation only, with member-change capability ambiguous from
documentation. BNB Chain's `tss-lib` supports member-changing reshare
but uses an older protocol generation (GG18/GG20). Cait-Sith (the
upstream from which NEAR's crate is derived) explicitly supports
member-changing reshare and the offline-party signing model but is
unaudited and the author warns it is experimental.

A direct dependency trace of the crate confirmed it is **cleanly
extractable**. The crate has zero NEAR-chain dependencies: no
`near-sdk`, no `nearcore`, no `near-primitives`, no `near-crypto`, no
indexer code. Its dependency tree consists of:

- Standard RustCrypto stack: `k256`, `ecdsa`, `elliptic-curve`,
  `sha2`, `sha3`, `hkdf`, `digest`, `subtle`, `zeroize`, `keccak`.
- Zcash Foundation FROST: `frost-core`, `frost-ed25519`,
  `frost-secp256k1`.
- Filecoin's `blstrs` for BLS12-381 (only used for the Confidential
  Key Derivation module, droppable for ECDSA-only deployments).
- Standard async (`futures`, `futures-lite`), serialization (`serde`,
  `borsh`, `rmp-serde`, etc.), and utility crates (`thiserror`,
  `derive_more`, `auto_ops`, `rand` family).
- A NEAR fork of Zcash's `reddsa` crate (only used for EdDSA, with a
  documented rationale relating to cheater-detection compatibility;
  could be replaced with upstream Zcash reddsa if pure-upstream
  dependencies are ever required).

For a Figure deployment using only secp256k1 ECDSA, the EdDSA, FROST,
and BLS-based CKD modules can all be ignored, leaving a minimal
dependency surface of standard RustCrypto plus async and serialization
plumbing. The workspace at `near/mpc` explicitly excludes the
`nearcore` submodule from its build (`exclude = ["libs/nearcore"]`),
confirming that the crypto crate's build does not require any NEAR
chain code even when built within the monorepo.

## OT-based ECDSA is the production protocol; robust ECDSA is not

The threshold-signatures crate provides two ECDSA variants:

- **Robust ECDSA** (`ecdsa::robust_ecdsa`): single offline-and-presign
  phase, then sign. Faster end-to-end when all parties are online,
  and provides graceful handling of malicious aborts.
- **OT-based ECDSA** (`ecdsa::ot_based_ecdsa`): three-phase pipeline
  (triple generation → presign → sign). Each phase can run with a
  different participant subset and threshold, subject only to the
  containment constraint that each subsequent set is contained in
  the previous one.

The two schemes are **cryptographically equivalent**: same primitive
(threshold ECDSA on secp256k1), same security model (actively-secure
under standard assumptions), same audit coverage. The signatures
they produce are indistinguishable from non-threshold ECDSA in both
cases. The choice between them is operational, not security-related.

For YLDS, the operational requirement decides: the IC must be offline
during routine signing. Robust ECDSA imposes a presign-time
constraint of `n ≥ 2t-1` participants. With `t = 2` and `n = 2` (the
holder + Figure subset attempting to sign), this requires
`2 ≥ 3`, which is false. Robust ECDSA cannot satisfy the offline-
custodian operational model in a 2-of-3 wallet. OT-based ECDSA has
no such constraint: any subset of size ≥ t can complete the entire
pipeline.

This is therefore not a tuning decision. **OT-based ECDSA is the
production protocol; robust ECDSA is unsuitable for this design.**

The trade-offs being accepted by choosing OT-based:

- **Performance under good conditions.** Robust ECDSA is faster
  end-to-end with all parties online; benchmarks suggest ~4–5× faster
  offline phase. For YLDS's anticipated low-to-moderate signing
  frequency, this difference is irrelevant.
- **Triple stockpiling.** OT-based explicitly supports pre-generating
  triples in advance and consuming them later, which can amortize the
  offline-phase cost across many signatures. This is a positive
  trade-off for YLDS, not a cost.
- **Performance under adversarial conditions.** Both schemes have
  identifiable abort. Robust ECDSA tends to handle malicious aborts
  more gracefully in the literature. For small committees with
  mostly cooperating parties this difference is marginal.

A caveat worth flagging: the audit scope of the threshold-signatures
crate should be verified directly with the audit report before
production deployment — specifically, which schemes were covered,
which extensions, and how thoroughly. There may also be implementation
details specific to this crate's variants that diverge from the
published Cait-Sith protocol it derives from. This applies equally
to both schemes; neither is disadvantaged on this front.

## What the spikes verified

Two test files were produced. Together they verify both required
properties.

### Spike 1: OT-based offline-custodian signing (`ot_offline_custodian.rs`)

This is the load-bearing spike. It directly verifies the operational
requirement. Two scenarios, both passing deterministically across
multiple runs:

**Scenario 1: routine signing without the custodian.** A 2-of-3
keygen ceremony involves all three parties (holder, Figure, custodian).
The custodian then becomes offline. Triple generation, presigning, and
signing are all driven by the {holder, Figure} subset only — the
custodian holds a keygen share but is absent from every subsequent
phase. The resulting ECDSA signature verifies against the wallet's
public key. ✓

**Scenario 2: recovery followed by routine signing without the
custodian.** The full UC2 recovery flow is run on OT-based ECDSA:
keygen with all three parties, then resharing-with-member-change
(holder is replaced by new_holder), then routine signing with
{new_holder, Figure} as the signing subset, custodian offline again.
The post-recovery signature verifies against the original public key.
✓

This spike confirms three things at once:

1. OT-based ECDSA does not have the `n ≥ 2t-1` constraint. Any
   subset of size ≥ t completes the entire pipeline.
2. Triple generation is also subset-only. The custodian does not
   need to participate in any phase of routine signing — including
   the pre-generation of triples that signing later consumes.
3. The operational model survives reshare-with-member-change. After
   recovery, the custodian remains offline for routine signing in
   the same way it was before recovery.

### Spike 2: Reshare with member change preserves the public key (`uc2_recovery.rs`)

This spike verifies the second property in isolation: resharing
across a changed participant set produces shares of the *same*
public key.

The test models the YLDS UC2 scenario at the minimum-meaningful
committee size: three parties holding a 2-of-3 threshold ECDSA key,
holder loses their share, Figure + custodian + new_holder drive
resharing. Five assertions verify keygen, reshare, public-key
preservation, functional signing, and signature verification against
the original public key. All five pass deterministically.

A note on this spike's protocol choice: it was originally written
against robust ECDSA, before the operational-model question had been
worked through. The reshare-with-member-change machinery is shared
between the OT-based and robust ECDSA schemes — both consume the same
DKG outputs. So the public-key-preservation result carries over to
OT-based ECDSA without re-verification, and Spike 1 Scenario 2
implicitly re-verifies it (it includes a reshare-with-member-change
followed by signing against the original public key on OT-based).

This spike is kept as part of the audit trail: it is a focused,
isolated verification of the public-key-preservation property,
useful as reference even though the production protocol is not the
one it tests against.

## Findings worth surfacing for the design memo

### The reshare API handles "lost participant" cleanly

The crate's `reshare` API takes both an old participant list and a
new participant list. Parties present in `new_participants` but absent
from the old keys carry `None` for their old share; parties present
in the old keys but absent from `new_participants` are simply not
spawned as protocol runners by the integration test harness. The
crate's internal protocol enforces that surviving old shares meet the
old threshold — which is exactly the `(n − lost) ≥ t` condition
flagged in the YLDS memo.

For UC2 specifically, this means "holder loses share" is modeled
naturally by simply omitting the holder from the new participant set
and from the share inputs; no special API is needed for "participant
gone" beyond the normal new-participant-set semantics.

### Public key as continuity anchor

The crate's `reshare` API requires the public key as an input to all
new participants, including those who had no prior share. New
participants pass `(None, public_key)` for `(old_share, public_key)`;
old participants pass `(Some(old_share), public_key)`. The protocol
enforces continuity: the resharing produces shares of *that specific
public key*, not an arbitrary key. The protocol fails loudly if
anything is inconsistent — there is no silent failure mode where the
public key drifts.

Stated more sharply: the public key is the identifier of a multi-
party-controlled key on Provenance, and the threshold-signatures
crate treats it as such. This aligns cleanly with the "asset binding"
reframe in the YLDS doc — the address is the persistent identity, and
key shares are subordinate to it.

### Triples can be batch-generated and stockpiled

OT-based ECDSA's three-phase structure means triples can be generated
in advance, by any subset meeting the threshold, and stored for later
consumption. For YLDS specifically, this means **holder + Figure can
pre-generate a stockpile of triples in a single ceremony**, store
them, and consume them across many later signing operations. Each
signing then only requires presign + sign (cheaper) once a triple is
available. The custodian is not involved in triple stockpile
generation either.

This is an architectural opportunity: triple stockpiling can be a
periodic background ceremony rather than something that happens
synchronously with each signing request. It does not affect
correctness — triples are deterministically one-time-use, with the
crate's API enforcing it — but it can improve perceived signing
latency.

### API ergonomics: minor surface details

A few details that only emerge from hands-on use:

- `MaxMalicious` and `ReconstructionLowerBound` implement
  `From<usize>`, not `From<u32>`. First-time users will hit this and
  wonder why their `let threshold: u32 = 2` doesn't compile.
- `AffinePoint` is private; the type for representing public-key
  values in tests is the non-generic `Element` alias from
  `ecdsa::Element`, not `Element<C>` from the crate root.
- `Tweak::derive_verifying_key` takes a `VerifyingKey<C>`, not a raw
  point or `Element`. Wrap with `frost_core::VerifyingKey::new(...)`
  to convert.

None of these are substantive; the cryptographic API is clean. They
are the kind of detail that surfaces only when you write code, not
when you read documentation, which is itself an argument for the
write-the-test-yourself approach rather than reasoning purely from
docs.

### Wait-indefinitely default

Per the crate documentation: *"All our public functions that involve
network interactions, such as keygen, reshare, sign, and ckd, are
designed to wait indefinitely for the expected messages... the caller
is responsible for managing potential issues, such as implementing
timeouts or other mechanisms to prevent functions from running
indefinitely."*

This is a deliberate design decision — the crypto layer doesn't
impose timeout policy because timeout policy depends on the
deployment context. For a production service, timeouts must be
implemented in the orchestration layer wrapping the crate, not
inside it. This is the correct boundary, but it is a non-trivial
responsibility for whoever operates the wrapping service.

## Implications for the YLDS recovery memo

The cryptographic side of YLDS's MPC architecture is no longer a
design risk. Specific updates the recovery memo should reflect:

- **OT-based ECDSA is the production protocol**
  (`threshold-signatures::ecdsa::ot_based_ecdsa`). Robust ECDSA is
  unsuitable because of its presign-time participant-count constraint.
  The two schemes are cryptographically equivalent; the choice is
  operational.

- **Routine signing is a 2-party operation between holder and Figure**
  in a 2-of-3 wallet. The IC participates in keygen at wallet creation
  and in structural ceremonies (recovery, divorce, refresh) but is
  offline during all routine signing.

- **Reshare-with-member-change preserves the public key** for any
  participant transition where surviving old participants meet the
  old threshold. UC2 (holder loses share, replaced by new_holder) is
  the canonical case; divorce (Figure removed) and refresh (same
  participants, fresh shares) are variants of the same primitive.

- **The "open question" item** titled *"Figure's current MPC scheme
  and its support for commitment-gated resharing"* can be amended to
  include a verified positive result for the candidate library
  (NEAR's threshold-signatures crate). The question of whether
  Figure's *existing* MPC infrastructure supports the same property
  remains open and depends on Figure publishing or otherwise
  disclosing their scheme's topology and resharing capabilities.

- **The asset-binding reframe** ("the asset is bound to the issuer's
  registry entry, not the private key") gains a complementary
  technical observation: in the threshold-signatures-crate model, the
  public key is the explicit identity that survives across share
  rotation, with the protocol enforcing continuity.

The remaining open questions for the YLDS recovery design — regulatory
feasibility of non-KYC co-signing, commitment-storage UX, registration
coverage, attestation-service integration, and Figure's existing MPC
topology — are not blocked by cryptographic feasibility and are the
ones to focus design energy on next.

## Reproducibility

The spikes were conducted in a Linux container with a fresh Rust 1.86
toolchain (auto-installed by rustup from the project's
`rust-toolchain.toml`). Steps to reproduce:

```
git clone https://github.com/near/mpc
cd mpc
# (optional) check out a specific commit for stable reproducibility

# Spike 1: OT-based offline-custodian signing (the load-bearing test):
cp ot_offline_custodian.rs crates/threshold-signatures/tests/
cargo test -p threshold-signatures --test ot_offline_custodian

# Spike 2: reshare-with-member-change on robust ECDSA (the original
# UC2 verification, kept for historical record):
cp uc2_recovery.rs crates/threshold-signatures/tests/
cargo test -p threshold-signatures --test uc2_recovery
```

Build time is approximately 5–10 minutes from cold cache. Test
runtimes are approximately 5 seconds for `ot_offline_custodian`
(which performs full OT-based triple generation, presign, and sign
cycles in two scenarios) and approximately 0.15 seconds for
`uc2_recovery`. Both tests pass deterministically across multiple
runs, though they consume fresh randomness per run for the
cryptographic protocols.

The full test sources are provided as separate files
(`ot_offline_custodian.rs` and `uc2_recovery.rs`) alongside this
report.
