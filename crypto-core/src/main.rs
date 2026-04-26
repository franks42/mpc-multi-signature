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
//!     {"msg_type":"begin_keygen","ceremony_id":"<uuid>","me":0,
//!      "peers":[0,1,2],"threshold":2,
//!      "share_path":"/abs/path/to/<role>/shares/<handle>.bin"}
//!     {"msg_type":"protocol_deliver","ceremony_id":"<uuid>",
//!      "from":<int>,"body":"<base64>"}
//!     {"msg_type":"cancel","ceremony_id":"<uuid>"}
//!
//!   outbound stdout (one JSON object per line):
//!     {"msg_type":"protocol_broadcast","ceremony_id":"<uuid>",
//!      "from":<int>,"body":"<base64>"}
//!     {"msg_type":"protocol_private","ceremony_id":"<uuid>",
//!      "from":<int>,"to":<int>,"body":"<base64>"}
//!     {"msg_type":"ceremony_complete","ceremony_id":"<uuid>",
//!      "public_key_hex":"<hex>","share_fingerprint":"<hex>"}
//!     {"msg_type":"ceremony_error","ceremony_id":"<uuid>",
//!      "category":"<string>","message":"<string>"}
//!
//! Share persistence: KeygenOutput is serialized via rmp-serde
//! (MessagePack) and written to `share_path`. The fingerprint is the
//! SHA-256 of those bytes, hex-encoded. The bb wrapper owns the
//! handle-to-path mapping; this binary just writes where told.
//!
//! Participants are integer ids (`Participant::from(u32)`); the bb
//! wrapper maps role keywords (:holder/:figure/:ic) to integers before
//! sending any JSON to this process.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use threshold_signatures::{
    ecdsa::Secp256K1Sha256,
    keygen,
    participants::Participant,
    protocol::{Action, Protocol},
    KeygenOutput, ReconstructionLowerBound,
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
        public_key_hex: String,
        share_fingerprint: String,
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

// ---------- Keygen driver ----------

fn run_keygen_ceremony(
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

    let mut protocol: Box<dyn Protocol<Output = KeygenOutput<Secp256K1Sha256>>> = Box::new(
        keygen::<Secp256K1Sha256>(&participants, me_p, threshold_lb, OsRng)
            .map_err(|e| anyhow!("keygen init failed: {:?}", e))?,
    );

    log_stderr(role, &format!("keygen initialized: me={me} peers={peers:?} threshold={threshold}"));

    loop {
        match protocol.poke().map_err(|e| anyhow!("protocol poke: {:?}", e))? {
            Action::Wait => {
                // Block on next stdin message.
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
                        return Ok(());
                    }
                    Inbound::BeginKeygen { .. } => {
                        return Err(anyhow!("unexpected begin_keygen mid-protocol"));
                    }
                }
            }
            Action::SendMany(data) => {
                write_outbound(
                    stdout,
                    &Outbound::ProtocolBroadcast {
                        ceremony_id: ceremony_id.clone(),
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
                        ceremony_id: ceremony_id.clone(),
                        from: me,
                        to: to_u32,
                        body: B64.encode(&data),
                    },
                )?;
            }
            Action::Return(out) => {
                // Public key as compressed sec1 bytes -> hex.
                let pk_bytes = out.public_key.serialize().map_err(|e| anyhow!("{:?}", e))?;
                let pk_hex = hex_encode(&pk_bytes);

                // Persist the share. rmp-serde uses KeygenOutput's
                // existing serde derives; SHA-256 over the bytes is
                // the content fingerprint.
                let share_bytes = rmp_serde::to_vec_named(&out)
                    .context("rmp-serde encode of KeygenOutput")?;
                let fp = sha256_hex(&share_bytes);
                write_share(&share_path, &share_bytes)
                    .with_context(|| format!("write share to {share_path}"))?;
                log_stderr(role, &format!(
                    "share written: {} bytes, fingerprint {fp} -> {share_path}",
                    share_bytes.len()
                ));

                write_outbound(
                    stdout,
                    &Outbound::CeremonyComplete {
                        ceremony_id: ceremony_id.clone(),
                        public_key_hex: pk_hex,
                        share_fingerprint: fp,
                    },
                )?;
                log_stderr(role, "keygen complete");
                return Ok(());
            }
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn write_share(path: &str, bytes: &[u8]) -> Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(p, bytes)?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
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

    // First inbound message must be begin_keygen for Stage 2.
    let mut first_line = String::new();
    let n = stdin_lock.read_line(&mut first_line)?;
    if n == 0 {
        return Err(anyhow!("stdin closed before begin_keygen"));
    }
    let first: Inbound = serde_json::from_str(first_line.trim())?;
    let result = match first {
        Inbound::BeginKeygen {
            ceremony_id,
            me,
            peers,
            threshold,
            share_path,
        } => run_keygen_ceremony(
            &role,
            ceremony_id,
            me,
            peers,
            threshold,
            share_path,
            &mut stdin_lock,
            &mut stdout_lock,
        ),
        other => Err(anyhow!("first message must be begin_keygen, got {other:?}")),
    };

    if let Err(e) = &result {
        // Best-effort error report. ceremony_id may not be available
        // on early failure; in that case the JSON lacks it and the bb
        // wrapper logs the unmatched error.
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
