//! mpc-crypto-core binary.
//!
//! One-shot Rust subprocess spawned by a party-bb wrapper for the
//! duration of a single ceremony. JSON-Lines stdio is the wire format
//! to the bb wrapper; bb does the EDN<->JSON translation outwards to
//! the orchestrator.
//!
//! Wire format (mirrors the design doc Appendix B):
//!
//!   inbound stdin (one JSON object per line):
//!     {"msg_type":"begin_keygen", "ceremony_id":"<uuid>", "me":0,
//!      "peers":[0,1,2], "threshold":2,
//!      "share_path":"/abs/path/<role>/shares/<handle>.bin"}
//!     {"msg_type":"begin_triples", ..., "triple_path":"..."}
//!     {"msg_type":"begin_presign", ..., "share_path":"...", "triple_path":"...",
//!      "presig_path":"..."}
//!     {"msg_type":"begin_sign", ..., "coordinator":<int>, "share_path":"...",
//!      "presig_path":"...", "digest_hex":"<32-byte hex>"}
//!     {"msg_type":"begin_reshare", "old_peers":[...], "old_threshold":N,
//!      "new_peers":[...], "new_threshold":M, "me":<int>,
//!      "old_share_path":<string|null>, "public_key_hex":"<hex>",
//!      "new_share_path":"..."}
//!     {"msg_type":"protocol_deliver", ..., "from":<int>, "body":"<base64>"}
//!     {"msg_type":"cancel", "ceremony_id":"..."}
//!
//!   outbound stdout (one JSON object per line):
//!     {"msg_type":"protocol_broadcast", ..., "from":<int>, "body":"<base64>"}
//!     {"msg_type":"protocol_private",   ..., "from":<int>, "to":<int>, "body":"<base64>"}
//!     {"msg_type":"ceremony_complete",  ..., "result": <ceremony-specific JSON map>}
//!     {"msg_type":"ceremony_error",     ..., "category":"...", "message":"..."}
//!
//! Persistence: rmp-serde encoded blobs.
//!   shares:  KeygenOutput<Secp256K1Sha256>
//!   triples: Vec<(TripleShare, TriplePub)> (length 2 — both triples for one signature)
//!   presigs: PresignOutput
//! Each ceremony reads its inputs from disk, writes its output to
//! disk, returns a content-hash fingerprint as the handle.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use elliptic_curve::ff::PrimeField;
use elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint};

use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            sign::sign,
            triples::{generate_triple_many, TriplePub, TripleShare},
            PresignArguments, PresignOutput, RerandomizedPresignOutput,
        },
        RerandomizationArguments, Scalar as EcdsaScalar, Secp256K1Sha256, Signature, Tweak,
    },
    frost_secp256k1::VerifyingKey,
    keygen,
    participants::Participant,
    protocol::{Action, Protocol},
    reshare, KeygenOutput, ParticipantList, ReconstructionLowerBound,
};

// ---------- Wire types ----------

#[derive(Debug, Deserialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
enum Inbound {
    BeginKeygen {
        ceremony_id: String,
        me: u32,
        peers: Vec<u32>,
        threshold: u32,
        share_path: String,
    },
    BeginTriples {
        ceremony_id: String,
        me: u32,
        peers: Vec<u32>,
        threshold: u32,
        triple_path: String,
    },
    BeginPresign {
        ceremony_id: String,
        me: u32,
        peers: Vec<u32>,
        threshold: u32,
        share_path: String,
        triple_path: String,
        presig_path: String,
    },
    BeginSign {
        ceremony_id: String,
        me: u32,
        peers: Vec<u32>,
        threshold: u32,
        coordinator: u32,
        share_path: String,
        presig_path: String,
        digest_hex: String,
    },
    BeginReshare {
        ceremony_id: String,
        me: u32,
        old_peers: Vec<u32>,
        old_threshold: u32,
        new_peers: Vec<u32>,
        new_threshold: u32,
        old_share_path: Option<String>,
        public_key_hex: String,
        new_share_path: String,
    },
    BeginShareProof {
        ceremony_id: String,
        me: u32,
        share_path: String,
        /// Hex-encoded bytes that the verifier supplies to bind the
        /// proof to a specific context — verifier nonce, ceremony id,
        /// ceremony purpose, etc. The Fiat-Shamir hash includes this
        /// verbatim so the proof is non-replayable across contexts.
        challenge_context_hex: String,
    },
    ProtocolDeliver {
        ceremony_id: String,
        from: u32,
        body: String, // base64
    },
    Cancel {
        ceremony_id: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
enum Outbound {
    ProtocolBroadcast {
        ceremony_id: String,
        from: u32,
        body: String,
    },
    ProtocolPrivate {
        ceremony_id: String,
        from: u32,
        to: u32,
        body: String,
    },
    CeremonyComplete {
        ceremony_id: String,
        result: serde_json::Value,
    },
    CeremonyError {
        ceremony_id: String,
        category: String,
        message: String,
    },
}

fn write_outbound(stdout: &mut io::StdoutLock<'_>, msg: &Outbound) -> Result<()> {
    serde_json::to_writer(&mut *stdout, msg)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn log_stderr(role: &str, msg: &str) {
    eprintln!("[mpc-crypto-core role={role}] {msg}");
}

// ---------- Persistence helpers ----------

fn write_blob(path: &str, bytes: &[u8]) -> Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(p, bytes)?;
    Ok(())
}

fn read_blob(path: &str) -> Result<Vec<u8>> {
    Ok(fs::read(path).with_context(|| format!("read {path}"))?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------- Generic protocol driver ----------

/// Drive a Protocol to completion via JSON-Lines stdio. The orchestrator
/// (via the bb wrapper) routes protocol_broadcast/protocol_private
/// messages between parties; we encode/decode the opaque MessageData as
/// base64.
fn drive_protocol<T>(
    role: &str,
    ceremony_id: &str,
    me: u32,
    mut protocol: Box<dyn Protocol<Output = T>>,
    stdin: &mut impl BufRead,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<T> {
    loop {
        match protocol.poke().map_err(|e| anyhow!("protocol poke: {:?}", e))? {
            Action::Wait => {
                let mut line = String::new();
                let n = stdin.read_line(&mut line)?;
                if n == 0 {
                    return Err(anyhow!("stdin closed mid-protocol"));
                }
                let inbound: Inbound = serde_json::from_str(line.trim())?;
                match inbound {
                    Inbound::ProtocolDeliver {
                        ceremony_id: cid,
                        from,
                        body,
                    } => {
                        if cid != ceremony_id {
                            return Err(anyhow!(
                                "ceremony-id mismatch: expected {ceremony_id} got {cid}"
                            ));
                        }
                        let bytes = B64.decode(body)?;
                        protocol
                            .message(Participant::from(from), bytes)
                            .map_err(|e| anyhow!("protocol message: {:?}", e))?;
                    }
                    Inbound::Cancel { ceremony_id: cid } => {
                        log_stderr(role, &format!("cancel received during protocol (ceremony {cid})"));
                        return Err(anyhow!("ceremony cancelled"));
                    }
                    other => {
                        return Err(anyhow!("unexpected message mid-protocol: {other:?}"));
                    }
                }
            }
            Action::SendMany(data) => {
                write_outbound(
                    stdout,
                    &Outbound::ProtocolBroadcast {
                        ceremony_id: ceremony_id.to_string(),
                        from: me,
                        body: B64.encode(&data),
                    },
                )?;
            }
            Action::SendPrivate(to, data) => {
                let to_u32: u32 = to.into();
                write_outbound(
                    stdout,
                    &Outbound::ProtocolPrivate {
                        ceremony_id: ceremony_id.to_string(),
                        from: me,
                        to: to_u32,
                        body: B64.encode(&data),
                    },
                )?;
            }
            Action::Return(out) => return Ok(out),
        }
    }
}

// ---------- Per-party verification share ----------
//
// X_i = x_i · G — the public commitment to a share's secret scalar.
// frost-core's SigningShare<C> is a tuple wrapping the inner scalar;
// .to_scalar() returns it. We multiply by secp256k1's generator and
// emit 33-byte sec1 compressed bytes — what verifiers compare
// against in Schnorr-PoK share-possession proofs.
fn verification_share_compressed(out: &KeygenOutput<Secp256K1Sha256>) -> [u8; 33] {
    let scalar_secp: EcdsaScalar = out.private_share.to_scalar();
    let big_x: ProjectivePoint = ProjectivePoint::GENERATOR * scalar_secp;
    let big_x_affine: AffinePoint = big_x.to_affine();
    let encoded = big_x_affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut buf = [0u8; 33];
    buf.copy_from_slice(bytes);
    buf
}

// ---------- Ceremony handlers ----------

fn handle_keygen(
    role: &str,
    ceremony_id: String,
    me: u32,
    peers: Vec<u32>,
    threshold: u32,
    share_path: String,
    stdin: &mut impl BufRead,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<()> {
    let participants: Vec<Participant> = peers.iter().copied().map(Participant::from).collect();
    let me_p = Participant::from(me);
    let threshold_lb = ReconstructionLowerBound::from(threshold as usize);

    let proto: Box<dyn Protocol<Output = KeygenOutput<Secp256K1Sha256>>> = Box::new(
        keygen::<Secp256K1Sha256>(&participants, me_p, threshold_lb, OsRng)
            .map_err(|e| anyhow!("keygen init: {:?}", e))?,
    );
    log_stderr(role, &format!("keygen me={me} peers={peers:?} threshold={threshold}"));

    let out = drive_protocol(role, &ceremony_id, me, proto, stdin, stdout)?;

    let pk_bytes = out.public_key.serialize().map_err(|e| anyhow!("{:?}", e))?;
    let pk_hex = hex::encode(&pk_bytes);
    let vshare_hex = hex::encode(verification_share_compressed(&out));
    let share_bytes = rmp_serde::to_vec_named(&out).context("rmp-serde encode KeygenOutput")?;
    let fp = sha256_hex(&share_bytes);
    write_blob(&share_path, &share_bytes)?;

    log_stderr(role, &format!("keygen complete: pk={pk_hex} share={share_path}"));
    write_outbound(
        stdout,
        &Outbound::CeremonyComplete {
            ceremony_id,
            result: serde_json::json!({
                "public_key_hex":         pk_hex,
                "verification_share_hex": vshare_hex,
                "share_fingerprint":      fp,
                "share_path":             share_path,
            }),
        },
    )?;
    Ok(())
}

fn handle_triples(
    role: &str,
    ceremony_id: String,
    me: u32,
    peers: Vec<u32>,
    threshold: u32,
    triple_path: String,
    stdin: &mut impl BufRead,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<()> {
    let participants: Vec<Participant> = peers.iter().copied().map(Participant::from).collect();
    let me_p = Participant::from(me);
    let threshold_lb = ReconstructionLowerBound::from(threshold as usize);

    let proto: Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>> = Box::new(
        generate_triple_many::<2>(&participants, me_p, threshold_lb, OsRng)
            .map_err(|e| anyhow!("triple-gen init: {:?}", e))?,
    );
    log_stderr(role, &format!("triple-gen me={me} peers={peers:?} threshold={threshold} (×2)"));

    let triples = drive_protocol(role, &ceremony_id, me, proto, stdin, stdout)?;

    if triples.len() != 2 {
        return Err(anyhow!("expected 2 triples, got {}", triples.len()));
    }
    let bytes = rmp_serde::to_vec_named(&triples).context("rmp-serde encode triples")?;
    let fp = sha256_hex(&bytes);
    write_blob(&triple_path, &bytes)?;

    log_stderr(role, &format!("triples complete: {triple_path}"));
    write_outbound(
        stdout,
        &Outbound::CeremonyComplete {
            ceremony_id,
            result: serde_json::json!({
                "triple_fingerprint": fp,
                "triple_path": triple_path,
            }),
        },
    )?;
    Ok(())
}

fn handle_presign(
    role: &str,
    ceremony_id: String,
    me: u32,
    peers: Vec<u32>,
    threshold: u32,
    share_path: String,
    triple_path: String,
    presig_path: String,
    stdin: &mut impl BufRead,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<()> {
    let participants: Vec<Participant> = peers.iter().copied().map(Participant::from).collect();
    let me_p = Participant::from(me);
    let threshold_lb = ReconstructionLowerBound::from(threshold as usize);

    let keygen_bytes = read_blob(&share_path)?;
    let keygen_out: KeygenOutput<Secp256K1Sha256> =
        rmp_serde::from_slice(&keygen_bytes).context("decode KeygenOutput")?;

    let triple_bytes = read_blob(&triple_path)?;
    let triples: Vec<(TripleShare, TriplePub)> =
        rmp_serde::from_slice(&triple_bytes).context("decode triples")?;
    if triples.len() != 2 {
        return Err(anyhow!("expected 2 triples on disk, got {}", triples.len()));
    }
    let mut iter = triples.into_iter();
    let triple0 = iter.next().unwrap();
    let triple1 = iter.next().unwrap();

    let proto: Box<dyn Protocol<Output = PresignOutput>> = Box::new(
        presign(
            &participants,
            me_p,
            PresignArguments {
                triple0,
                triple1,
                keygen_out,
                threshold: threshold_lb,
            },
        )
        .map_err(|e| anyhow!("presign init: {:?}", e))?,
    );
    log_stderr(role, &format!("presign me={me} peers={peers:?}"));

    let presig = drive_protocol(role, &ceremony_id, me, proto, stdin, stdout)?;

    let bytes = rmp_serde::to_vec_named(&presig).context("rmp-serde encode PresignOutput")?;
    let fp = sha256_hex(&bytes);
    write_blob(&presig_path, &bytes)?;

    log_stderr(role, &format!("presign complete: {presig_path}"));
    write_outbound(
        stdout,
        &Outbound::CeremonyComplete {
            ceremony_id,
            result: serde_json::json!({
                "presig_fingerprint": fp,
                "presig_path": presig_path,
            }),
        },
    )?;
    Ok(())
}

fn handle_sign(
    role: &str,
    ceremony_id: String,
    me: u32,
    peers: Vec<u32>,
    threshold: u32,
    coordinator: u32,
    share_path: String,
    presig_path: String,
    digest_hex: String,
    stdin: &mut impl BufRead,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<()> {
    let participants: Vec<Participant> = peers.iter().copied().map(Participant::from).collect();
    let me_p = Participant::from(me);
    let coord_p = Participant::from(coordinator);
    let threshold_lb = ReconstructionLowerBound::from(threshold as usize);

    // Load the keygen output (for public_key) and the presignature.
    let keygen_bytes = read_blob(&share_path)?;
    let keygen_out: KeygenOutput<Secp256K1Sha256> =
        rmp_serde::from_slice(&keygen_bytes).context("decode KeygenOutput")?;
    let presig_bytes = read_blob(&presig_path)?;
    let presig: PresignOutput =
        rmp_serde::from_slice(&presig_bytes).context("decode PresignOutput")?;

    // Decode the 32-byte digest from hex.
    let digest = hex::decode(&digest_hex).context("digest hex decode")?;
    if digest.len() != 32 {
        return Err(anyhow!("digest must be 32 bytes, got {}", digest.len()));
    }
    let mut digest32 = [0u8; 32];
    digest32.copy_from_slice(&digest);
    let msg_hash: EcdsaScalar = EcdsaScalar::from_repr(digest32.into())
        .into_option()
        .ok_or_else(|| anyhow!("digest not a valid secp256k1 scalar"))?;

    // Rerandomize the presignature with a zero tweak — derived_pk = pk,
    // so the resulting signature still verifies against the original pk.
    // For Stage 4 we use deterministic zero entropy; production deployments
    // would supply fresh entropy per signature.
    let pk_affine: AffinePoint = keygen_out.public_key.to_element().to_affine();
    let zero_tweak = Tweak::new(EcdsaScalar::ZERO);
    let participant_list = ParticipantList::new(&participants)
        .ok_or_else(|| anyhow!("invalid participant list"))?;
    let rerand_args = RerandomizationArguments::new(
        pk_affine,
        zero_tweak,
        digest32,
        presig.big_r,
        participant_list,
        [0u8; 32], // entropy — Stage 4 deterministic; production needs fresh
    );
    let rerand_presig = RerandomizedPresignOutput::rerandomize_presign(&presig, &rerand_args)
        .map_err(|e| anyhow!("rerandomize: {:?}", e))?;

    let proto: Box<dyn Protocol<Output = Option<Signature>>> = Box::new(
        sign(
            &participants,
            coord_p,
            threshold_lb,
            me_p,
            pk_affine,
            rerand_presig,
            msg_hash,
        )
        .map_err(|e| anyhow!("sign init: {:?}", e))?,
    );
    log_stderr(role, &format!("sign me={me} peers={peers:?} coordinator={coordinator}"));

    let sig_option = drive_protocol(role, &ceremony_id, me, proto, stdin, stdout)?;

    // Coordinator gets Some(sig); others get None.
    let result = match sig_option {
        Some(sig) => {
            // Convert (big_r, s) → standard (r, s) for interop. r is x-coord of big_r.
            let r_scalar = scalar_x_of(&sig.big_r);
            let r_bytes: [u8; 32] = r_scalar.to_repr().into();
            let s_bytes: [u8; 32] = sig.s.to_repr().into();
            let mut raw64 = [0u8; 64];
            raw64[..32].copy_from_slice(&r_bytes);
            raw64[32..].copy_from_slice(&s_bytes);
            serde_json::json!({
                "signature_hex": hex::encode(raw64),
                "is_coordinator": true,
            })
        }
        None => serde_json::json!({
            "signature_hex": serde_json::Value::Null,
            "is_coordinator": false,
        }),
    };

    log_stderr(role, "sign complete");
    write_outbound(
        stdout,
        &Outbound::CeremonyComplete {
            ceremony_id,
            result,
        },
    )?;
    Ok(())
}

fn handle_reshare(
    role: &str,
    ceremony_id: String,
    me: u32,
    old_peers: Vec<u32>,
    old_threshold: u32,
    new_peers: Vec<u32>,
    new_threshold: u32,
    old_share_path: Option<String>,
    public_key_hex: String,
    new_share_path: String,
    stdin: &mut impl BufRead,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<()> {
    let old_participants: Vec<Participant> =
        old_peers.iter().copied().map(Participant::from).collect();
    let new_participants: Vec<Participant> =
        new_peers.iter().copied().map(Participant::from).collect();
    let me_p = Participant::from(me);
    let old_t = ReconstructionLowerBound::from(old_threshold as usize);
    let new_t = ReconstructionLowerBound::from(new_threshold as usize);

    // Old signing share: Some for old participants, None for new-only participants.
    let old_signing_key = match old_share_path.as_deref() {
        Some(p) => {
            let bytes = read_blob(p)?;
            let kg: KeygenOutput<Secp256K1Sha256> =
                rmp_serde::from_slice(&bytes).context("decode old KeygenOutput")?;
            Some(kg.private_share)
        }
        None => None,
    };

    // Old public key — required as continuity anchor.
    let pk_bytes = hex::decode(&public_key_hex).context("public_key_hex decode")?;
    let old_public_key: VerifyingKey =
        VerifyingKey::deserialize(&pk_bytes).map_err(|e| anyhow!("decode pk: {:?}", e))?;

    let proto: Box<dyn Protocol<Output = KeygenOutput<Secp256K1Sha256>>> = Box::new(
        reshare::<Secp256K1Sha256>(
            &old_participants,
            old_t,
            old_signing_key,
            old_public_key,
            &new_participants,
            new_t,
            me_p,
            OsRng,
        )
        .map_err(|e| anyhow!("reshare init: {:?}", e))?,
    );
    log_stderr(
        role,
        &format!("reshare me={me} old={old_peers:?}/{old_threshold} new={new_peers:?}/{new_threshold}"),
    );

    let new_kg = drive_protocol(role, &ceremony_id, me, proto, stdin, stdout)?;

    let new_pk_bytes = new_kg.public_key.serialize().map_err(|e| anyhow!("{:?}", e))?;
    let new_pk_hex = hex::encode(&new_pk_bytes);
    let new_vshare_hex = hex::encode(verification_share_compressed(&new_kg));
    let bytes = rmp_serde::to_vec_named(&new_kg).context("rmp-serde encode KeygenOutput")?;
    let fp = sha256_hex(&bytes);
    write_blob(&new_share_path, &bytes)?;

    if new_pk_hex != public_key_hex {
        // Sanity: reshare must preserve the public key.
        return Err(anyhow!(
            "reshare PK changed! expected {public_key_hex} got {new_pk_hex}"
        ));
    }

    log_stderr(role, &format!("reshare complete: pk preserved, share={new_share_path}"));
    write_outbound(
        stdout,
        &Outbound::CeremonyComplete {
            ceremony_id,
            result: serde_json::json!({
                "public_key_hex":         new_pk_hex,
                "verification_share_hex": new_vshare_hex,
                "share_fingerprint":      fp,
                "share_path":             new_share_path,
            }),
        },
    )?;
    Ok(())
}

// ---------- Share-possession proof handler ----------

fn handle_share_proof(
    role: &str,
    ceremony_id: String,
    _me: u32,
    share_path: String,
    challenge_context_hex: String,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<()> {
    let keygen_bytes = read_blob(&share_path)?;
    let keygen_out: KeygenOutput<Secp256K1Sha256> =
        rmp_serde::from_slice(&keygen_bytes).context("decode KeygenOutput")?;

    let challenge_context =
        hex::decode(&challenge_context_hex).context("decode challenge_context_hex")?;

    let x_i: EcdsaScalar = keygen_out.private_share.to_scalar();
    let big_x_compressed = verification_share_compressed(&keygen_out);

    let transcript = schnorr_pok_share(&x_i, &big_x_compressed, &challenge_context);

    log_stderr(role, "share-possession proof produced");
    write_outbound(
        stdout,
        &Outbound::CeremonyComplete {
            ceremony_id,
            result: serde_json::json!({
                "verification_share_hex": hex::encode(big_x_compressed),
                "proof_hex":              hex::encode(transcript),
            }),
        },
    )?;
    Ok(())
}

// ---------- Schnorr proof of knowledge of share x_i ----------
//
// Public input:  X_i = x_i · G    (33-byte compressed; the verifier
//                                   already has this from keygen)
//                challenge_context (verifier-supplied bytes —
//                                   nonce, ceremony id, identity-key
//                                   binding, etc.)
// Private input: x_i               (the share scalar, loaded from disk)
//
// Proof:
//   pick r ← Z_n
//   R = r · G
//   c = SHA-256(R_compressed || X_i_compressed || challenge_context)
//   s = r + c · x_i mod n
//   transcript = (R_compressed, s_bytes)         33 + 32 = 65 bytes raw
//
// Verification (orchestrator side):
//   recompute c from received R_compressed + X_i + context
//   check  s · G == R + c · X_i
//
// The challenge context is the binding mechanism: Stage 5a uses it
// for verifier-nonce + ceremony-id; Stage 5a's identity-binding
// extension layers in the Ed25519 identity public key.

fn schnorr_pok_share(
    x_i: &EcdsaScalar,
    big_x_compressed: &[u8; 33],
    challenge_context: &[u8],
) -> [u8; 65] {
    use rand_core::RngCore;

    // 1. r ← Z_n.
    //    rand_core 0.6 + k256 0.13 don't expose a one-call
    //    "random_nonzero scalar" without extra plumbing; we sample
    //    32 bytes and reduce, retrying on the rare zero result.
    let r: EcdsaScalar = loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Some(s) = EcdsaScalar::from_repr(bytes.into()).into_option() {
            if !bool::from(s.is_zero()) {
                break s;
            }
        }
    };

    // 2. R = r · G.
    let big_r = ProjectivePoint::GENERATOR * r;
    let big_r_affine = big_r.to_affine();
    let big_r_encoded = big_r_affine.to_encoded_point(true);
    let big_r_compressed: [u8; 33] = {
        let mut buf = [0u8; 33];
        buf.copy_from_slice(big_r_encoded.as_bytes());
        buf
    };

    // 3. c = SHA-256(R || X_i || context).
    let mut hasher = Sha256::new();
    hasher.update(big_r_compressed);
    hasher.update(big_x_compressed);
    hasher.update(challenge_context);
    let c_digest = hasher.finalize();

    // Reduce SHA-256 output mod n. For secp256k1 this is well-defined:
    // map 32 bytes → scalar via from_repr; on the rare overflow case
    // (probability ~2^-128) the protocol allows fallback.
    let c: EcdsaScalar = EcdsaScalar::from_repr(c_digest.into())
        .into_option()
        .unwrap_or(EcdsaScalar::ZERO);

    // 4. s = r + c · x_i.
    let s: EcdsaScalar = r + c * x_i;
    let s_repr: [u8; 32] = s.to_repr().into();

    // 5. Pack transcript: R || s.
    let mut out = [0u8; 65];
    out[..33].copy_from_slice(&big_r_compressed);
    out[33..].copy_from_slice(&s_repr);
    out
}

// ---------- secp256k1 x-coordinate helper ----------
//
// The threshold-signatures crate's `x_coordinate(&AffinePoint) -> Scalar`
// is `pub(crate)`, not exposed. Re-implement using the public k256 API:
// the affine x-coordinate, reduced modulo the curve order. Standard
// ECDSA spec: r = x mod n.
fn scalar_x_of(p: &AffinePoint) -> EcdsaScalar {
    let enc = p.to_encoded_point(false); // uncompressed → has explicit x
    let x_bytes = enc.x().expect("point is not at infinity");
    let arr: [u8; 32] = (*x_bytes).into();
    EcdsaScalar::from_repr(arr.into())
        .into_option()
        .unwrap_or_else(|| {
            // x ≥ curve order — astronomically rare; panic with a hint
            // since the spike doesn't need to handle this case for Stage 4.
            panic!("affine x ≥ curve order — non-canonical r; explicit reduction TODO")
        })
}

// ---------- CLI ----------

fn parse_role(args: &[String]) -> Result<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == "--role" {
            return iter
                .next()
                .cloned()
                .ok_or_else(|| anyhow!("--role expects a value"));
        }
    }
    Err(anyhow!("missing --role flag"))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let role = parse_role(&args)?;
    log_stderr(&role, "started");

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    let mut first_line = String::new();
    let n = stdin_lock.read_line(&mut first_line)?;
    if n == 0 {
        return Err(anyhow!("stdin closed before begin_*"));
    }
    let first: Inbound = serde_json::from_str(first_line.trim())?;

    let result: Result<()> = match first {
        Inbound::BeginKeygen {
            ceremony_id,
            me,
            peers,
            threshold,
            share_path,
        } => handle_keygen(
            &role,
            ceremony_id,
            me,
            peers,
            threshold,
            share_path,
            &mut stdin_lock,
            &mut stdout_lock,
        ),

        Inbound::BeginTriples {
            ceremony_id,
            me,
            peers,
            threshold,
            triple_path,
        } => handle_triples(
            &role,
            ceremony_id,
            me,
            peers,
            threshold,
            triple_path,
            &mut stdin_lock,
            &mut stdout_lock,
        ),

        Inbound::BeginPresign {
            ceremony_id,
            me,
            peers,
            threshold,
            share_path,
            triple_path,
            presig_path,
        } => handle_presign(
            &role,
            ceremony_id,
            me,
            peers,
            threshold,
            share_path,
            triple_path,
            presig_path,
            &mut stdin_lock,
            &mut stdout_lock,
        ),

        Inbound::BeginSign {
            ceremony_id,
            me,
            peers,
            threshold,
            coordinator,
            share_path,
            presig_path,
            digest_hex,
        } => handle_sign(
            &role,
            ceremony_id,
            me,
            peers,
            threshold,
            coordinator,
            share_path,
            presig_path,
            digest_hex,
            &mut stdin_lock,
            &mut stdout_lock,
        ),

        Inbound::BeginReshare {
            ceremony_id,
            me,
            old_peers,
            old_threshold,
            new_peers,
            new_threshold,
            old_share_path,
            public_key_hex,
            new_share_path,
        } => handle_reshare(
            &role,
            ceremony_id,
            me,
            old_peers,
            old_threshold,
            new_peers,
            new_threshold,
            old_share_path,
            public_key_hex,
            new_share_path,
            &mut stdin_lock,
            &mut stdout_lock,
        ),

        Inbound::BeginShareProof {
            ceremony_id,
            me,
            share_path,
            challenge_context_hex,
        } => handle_share_proof(
            &role,
            ceremony_id,
            me,
            share_path,
            challenge_context_hex,
            &mut stdout_lock,
        ),

        other => Err(anyhow!("first message must be a begin_* variant, got {other:?}")),
    };

    if let Err(e) = &result {
        let err_msg = Outbound::CeremonyError {
            ceremony_id: String::new(),
            category: "internal".to_string(),
            message: e.to_string(),
        };
        let _ = write_outbound(&mut stdout_lock, &err_msg);
        log_stderr(&role, &format!("error: {e}"));
    }
    result
}
