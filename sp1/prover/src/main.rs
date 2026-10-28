//! pg-prover: the host side of the Pool Guard SP1 route. One process per call; the app runs it
//! with child_process and reads one JSON object from stdout. Errors go to stderr, exit code 1.
//!
//!   pg-prover vkey    --elf <path>
//!       { "vkey": "0x…" }                      the program's verifying key, as the verifier wants it
//!   pg-prover sign    --key <hex> --record <json>
//!       { "signature": "0x…", "issuer": "0x…" } the issuer signs a record (tests; the app signs in JS)
//!   pg-prover digest  --record <json>
//!       { "digest": "0x…" }                    the 32 bytes the issuer signs, for cross-checking the app
//!   pg-prover execute --elf <path> --input <json>
//!       { "publicValues": "0x…", "cycles": n, … }  runs the program with no proof: the cheap check
//!   pg-prover prove   --elf <path> --input <json> [--out <path>]
//!       { "proof": "0x…", "publicValues": "0x…", "vkey", "decoded" }  a Groth16 proof made here, on
//!       the CPU; the wrap runs in Succinct's Docker image (16 GB RAM). This is what the GitHub
//!       Actions prover runs (.github/workflows/prove.yml).
//!   pg-prover request --elf <path> --input <json>
//!       { "requestId": "0x…" }                 asks the Succinct network for a Groth16 proof
//!   pg-prover status  --request <id>
//!       { "status": "requested|assigned|fulfilled|unfulfillable", "proof"?, "publicValues"? }
//!
//! Network settings come from the environment, as the SDK reads them: NETWORK_PRIVATE_KEY and,
//! optionally, NETWORK_RPC_URL. The `--input` JSON is { record: { sheet, hook, wallet, limit,
//! listed, ts }, signature, covered }, hex strings except `listed` (bool) and `ts` (number);
//! `limit` and `covered` may be decimal.
use std::{fs, path::PathBuf, time::Duration};

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use anyhow::{anyhow, bail, Context, Result};
use pool_guard_types::{Input, PublicValues, Record};
use serde::{Deserialize, Serialize};
use sp1_sdk::{prelude::*, Elf, ProverClient, SP1Stdin};

#[derive(Deserialize)]
struct RecordJson { sheet: String, hook: String, wallet: String, limit: String, listed: bool, ts: u64 }
#[derive(Deserialize)]
struct InputJson { record: RecordJson, signature: String, covered: String }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Decoded { sheet: String, hook: String, wallet: String, covered: String, listed: bool, fits: bool, issuer: String, ts: u64 }

fn hexbytes(s: &str, what: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).with_context(|| format!("{what}: not hex"))
}
fn fixed<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let b = hexbytes(s, what)?;
    if b.len() != N { bail!("{what}: expected {N} bytes, got {}", b.len()); }
    Ok(b.try_into().unwrap())
}
/// a decimal amount, or hex when 0x-prefixed, as 32 big-endian bytes
fn amount(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = if let Some(h) = s.strip_prefix("0x") { U256::from_str_radix(h, 16) } else { U256::from_str_radix(s, 10) }
        .with_context(|| format!("{what}: not a number"))?;
    Ok(v.to_be_bytes())
}
fn record(r: &RecordJson) -> Result<Record> {
    Ok(Record { sheet: fixed::<32>(&r.sheet, "sheet")?, hook: fixed::<20>(&r.hook, "hook")?, wallet: fixed::<20>(&r.wallet, "wallet")?, limit: amount(&r.limit, "limit")?, listed: r.listed, ts: r.ts })
}
fn input(path: &str) -> Result<Input> {
    let j: InputJson = serde_json::from_str(&fs::read_to_string(path).with_context(|| format!("reading {path}"))?)?;
    Ok(Input { record: record(&j.record)?, signature: hexbytes(&j.signature, "signature")?, covered: amount(&j.covered, "covered")? })
}
fn elf(path: &PathBuf) -> Result<Elf> {
    Ok(Elf::from(fs::read(path).with_context(|| format!("reading the ELF at {}", path.display()))?))
}
fn stdin_for(i: &Input) -> SP1Stdin { let mut s = SP1Stdin::new(); s.write(i); s }

fn decode(pv: &[u8]) -> Result<Decoded> {
    let v = PublicValues::abi_decode(pv).map_err(|e| anyhow!("public values do not decode: {e}"))?;
    Ok(Decoded { sheet: v.sheet.to_string(), hook: v.hook.to_string(), wallet: v.wallet.to_string(), covered: v.covered.to_string(), listed: v.listed, fits: v.fits, issuer: v.issuer.to_string(), ts: v.ts })
}
fn out<T: Serialize>(v: &T) { println!("{}", serde_json::to_string(v).unwrap()); }

fn arg(args: &[String], name: &str) -> Result<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone()).ok_or_else(|| anyhow!("missing {name}"))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await { eprintln!("pg-prover: {e:#}"); std::process::exit(1); }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    // the SDK's stage log (RUST_LOG=info): the Actions log shows where a slow proof is
    if matches!(cmd, "prove" | "execute") { sp1_sdk::utils::setup_logger(); }
    match cmd {
        "vkey" => {
            let client = ProverClient::builder().cpu().build().await;
            let pk = client.setup(elf(&PathBuf::from(arg(&args, "--elf")?))?).await?;
            out(&serde_json::json!({ "vkey": pk.verifying_key().bytes32() }));
        }
        "sign" => {
            let signer: PrivateKeySigner = arg(&args, "--key")?.parse().context("bad --key")?;
            let r: RecordJson = serde_json::from_str(&arg(&args, "--record")?)?;
            let rec = record(&r)?;
            let sig = signer.sign_hash_sync(&rec.digest())?;
            let mut bytes = sig.as_bytes().to_vec();
            // alloy writes v as 27/28; the program takes either form
            if bytes[64] < 27 { bytes[64] += 27; }
            out(&serde_json::json!({ "signature": format!("0x{}", hex::encode(bytes)), "issuer": signer.address().to_string(), "digest": rec.digest().to_string() }));
        }
        "digest" => {
            // the digest the app must sign, for cross-checking the JS signer against this crate
            let r: RecordJson = serde_json::from_str(&arg(&args, "--record")?)?;
            out(&serde_json::json!({ "digest": record(&r)?.digest().to_string() }));
        }
        "execute" => {
            let i = input(&arg(&args, "--input")?)?;
            let client = ProverClient::builder().cpu().build().await;
            let (pv, report) = client.execute(elf(&PathBuf::from(arg(&args, "--elf")?))?, stdin_for(&i)).await?;
            let bytes = pv.to_vec();
            out(&serde_json::json!({ "publicValues": format!("0x{}", hex::encode(&bytes)), "decoded": decode(&bytes)?, "cycles": report.total_instruction_count() }));
        }
        "prove" => {
            let i = input(&arg(&args, "--input")?)?;
            let client = ProverClient::builder().cpu().build().await;
            let pk = client.setup(elf(&PathBuf::from(arg(&args, "--elf")?))?).await?;
            let p = client.prove(&pk, stdin_for(&i)).groth16().await?;
            client.verify(&p, pk.verifying_key(), None).map_err(|e| anyhow!("the proof made here does not verify: {e}"))?;
            let pv = p.public_values.to_vec();
            let out_json = serde_json::json!({ "proof": format!("0x{}", hex::encode(p.bytes())), "publicValues": format!("0x{}", hex::encode(&pv)), "decoded": decode(&pv)?, "vkey": pk.verifying_key().bytes32(), "sp1Version": p.sp1_version });
            if let Ok(path) = arg(&args, "--out") { fs::write(&path, serde_json::to_string(&out_json)?).with_context(|| format!("writing {path}"))?; }
            out(&out_json);
        }
        "request" => {
            let i = input(&arg(&args, "--input")?)?;
            let client = ProverClient::builder().network().build().await;
            let pk = client.setup(elf(&PathBuf::from(arg(&args, "--elf")?))?).await?;
            let id = client.prove(&pk, stdin_for(&i)).groth16().timeout(Duration::from_secs(900)).request().await?;
            out(&serde_json::json!({ "requestId": id.to_string(), "vkey": pk.verifying_key().bytes32() }));
        }
        "status" => {
            let id: B256 = arg(&args, "--request")?.parse().context("bad --request")?;
            let client = ProverClient::builder().network().build().await;
            let (status, proof) = client.get_proof_status(id).await?;
            // the proto numbers: 1 requested, 2 assigned, 3 fulfilled, 4 unfulfillable
            let fs: i32 = status.fulfillment_status();
            let name = match fs { 1 => "requested", 2 => "assigned", 3 => "fulfilled", 4 => "unfulfillable", _ => "unknown" };
            match proof {
                Some(p) if fs == 3 => {
                    let pv = p.public_values.to_vec();
                    out(&serde_json::json!({ "status": name, "proof": format!("0x{}", hex::encode(p.bytes())), "publicValues": format!("0x{}", hex::encode(&pv)), "decoded": decode(&pv)?, "sp1Version": p.sp1_version }));
                }
                _ => out(&serde_json::json!({ "status": name })),
            }
        }
        "address" => {
            let key = hexbytes(&arg(&args, "--pubkey")?, "pubkey")?;
            out(&serde_json::json!({ "address": Address::from_slice(&keccak256(&key[1..])[12..]).to_string() }));
        }
        _ => bail!("usage: pg-prover vkey|sign|digest|execute|prove|request|status …"),
    }
    Ok(())
}
