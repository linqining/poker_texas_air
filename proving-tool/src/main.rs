//! `prove-hand` — one-shot CLI for the poker `proved` settlement mode.
//!
//! Wraps the (patched) starkware-libs/proving stack vendored under `third_party/proving`:
//! Cairo1 source -> gas-disabled `Executable` compile -> Cairo VM witness run -> Stwo proof
//! -> verification, with per-phase timings and all artifacts written to an output directory.
//!
//! The game server never runs this; it is a standalone tool for whoever settles a hand in
//! `STARKNET_SETTLE_MODE=proved`. See README.md for the mode story.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use cairo_air::utils::{
    ProofFormat, deserialize_proof_from_file, get_verification_output, serialize_proof_to_file,
};
use cairo_air::verifier::{verify_cairo, verify_cairo_ex};
use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use serde_json::json;
use stwo::core::fri::FriConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_adapter::ExecutionResources;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_dev_utils::cairo1_compile::compile_cairo1_executable;
use stwo_cairo_dev_utils::vm_utils::{ProgramType, run_and_adapt};
use stwo_cairo_prover::prover::{ChannelHash, LiftingSizePolicy, ProverParameters, prove_cairo};

/// Bench programs shipped with the vendored proving repo.
const BENCH_TEMPLATE: &str = include_str!("bench_template.cairo");
const BENCH_DIR_REL: &str = "third_party/proving/test_data/test_hand_verify_bench";
/// Corelib crate root (the dir containing `lib.cairo`), not the repo root.
const CORELIB_REL: &str = "third_party/corelib-2.19.4/corelib/src";

#[derive(Parser, Debug)]
#[command(
    name = "prove-hand",
    about = "Cairo1 -> Stwo prove/verify pipeline for the poker `proved` settlement mode",
    version
)]
struct Args {
    /// Cairo1 source program. Defaults to the hand_verify bench at --scale.
    #[arg(long)]
    program: Option<PathBuf>,
    /// corelib crate dir used to compile --program (defaults to the vendored v2.19.4 corelib).
    #[arg(long)]
    corelib: Option<PathBuf>,
    /// Optional JSON file with program arguments: an array of hex felt strings, e.g. ["0x1","0x2"].
    #[arg(long)]
    inputs: Option<PathBuf>,
    /// small | medium | full, or a number N to generate a custom bench with N challenges
    /// (N_EC = N*148/22, PAYLOAD_LEN = N*70/22). Default: full.
    #[arg(long, default_value = "full")]
    scale: String,
    /// Output directory for executable.json / proof / public outputs / summary.json.
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// Proof serialization format: json | binary | cairo_serde.
    #[arg(long, value_enum, default_value_t = ProofFormat::Json)]
    proof_format: ProofFormat,
    /// JSON file with prover parameters (same schema as run_and_prove --params_json).
    /// Defaults to the 96-bit-security production parameters.
    #[arg(long)]
    params: Option<PathBuf>,
    /// Only verify an existing proof (no compile/run/prove). Reads --proof, or
    /// <out-dir>/proof.<json|bin> if --proof is not given.
    #[arg(long)]
    check_only: bool,
    /// Proof file to verify with --check-only.
    #[arg(long, requires = "check_only")]
    proof: Option<PathBuf>,
}

fn main() -> Result<()> {
    // Progress logs from the prover (phase spans) go to stderr; the report goes to stdout.
    // The salsa/cairo-lang compiler logs are extremely chatty at INFO, so default to WARN;
    // set PROVE_HAND_LOG=debug|info for full tracing output.
    let level = match std::env::var("PROVE_HAND_LOG").as_deref() {
        Ok("debug") | Ok("trace") => tracing::Level::DEBUG,
        Ok("info") => tracing::Level::INFO,
        Ok("off") | Ok("error") => tracing::Level::ERROR,
        _ => tracing::Level::WARN,
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_max_level(level)
        // 段关闭时打印 busy time（ms）——用于 prove 内部相位分解。
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let args = Args::parse();

    // Warm rayon's global pool (all cores) BEFORE the compile phase: the Cairo1 compiler setup
    // sets RAYON_NUM_THREADS=1 in-process, and the pool is built lazily from the env on first
    // parallel use — without this the prove phase below would run single-threaded (~8x slower).
    rayon::broadcast(|_| {});
    let root = repo_root();
    let scale = parse_scale(&args.scale)?;
    let out_dir =
        args.out_dir.clone().unwrap_or_else(|| root.join("proving-tool/output").join(scale.label()));
    fs::create_dir_all(&out_dir).with_context(|| format!("mkdir {}", out_dir.display()))?;

    if args.check_only {
        return check_only(&args, &out_dir);
    }

    let program = resolve_program(&args, &root, &scale, &out_dir)?;
    let corelib = args.corelib.clone().unwrap_or_else(|| root.join(CORELIB_REL));
    let proof_path = out_dir.join(proof_file_name(&args.proof_format));

    println!("prove-hand: scale={} format={}", scale.label(), format_name(&args.proof_format));
    println!("  program : {}", program.display());
    println!("  corelib : {}", corelib.display());
    println!("  out-dir : {}", out_dir.display());

    let total = Instant::now();

    // 1. Compile Cairo1 -> Executable (gas-disabled; see third_party/proving fixes).
    let t = Instant::now();
    let executable = compile_cairo1_executable(&program, Some(&corelib))
        .with_context(|| format!("compile {}", program.display()))?;
    let compile_dur = t.elapsed();
    let executable_path = out_dir.join("executable.json");
    write_json(&executable_path, &serde_json::to_value(&executable)?)?;

    // 2. Run the witness + adapt to the Stwo prover input.
    let t = Instant::now();
    let prover_input = run_and_adapt(
        &executable_path,
        ProgramType::Executable,
        LayoutName::all_cairo_stwo,
        args.inputs.as_ref(),
    )
    .context("run witness (Cairo VM)")?;
    let run_dur = t.elapsed();
    let resources = ExecutionResources::from_prover_input(&prover_input);
    // `verify_instruction` counts unique PCs; the trace length (VM steps) is the sum of the
    // per-opcode instance counts.
    let steps: usize = resources.opcodes_instance_counter.values().sum();

    // 3. Prove.
    let params = load_params(&args)?;
    let t = Instant::now();
    let proof = prove_cairo::<Blake2sMerkleChannel>(prover_input, params.clone())
        .context("prove (stwo)")?;
    let prove_dur = t.elapsed();

    // 4. Verify (standalone, against the serialized claim).
    let t = Instant::now();
    let public_memory = proof.claim.public_data.public_memory.clone();
    let verification = get_verification_output(&public_memory);
    verify_cairo_ex::<Blake2sMerkleChannel>(proof.clone().into(), params.include_all_preprocessed_columns)
        .context("proof verification FAILED")?;
    let verify_dur = t.elapsed();

    // 5. Serialize artifacts.
    let t = Instant::now();
    serialize_proof_to_file(&proof, &proof_path, args.proof_format.clone())
        .with_context(|| format!("write {}", proof_path.display()))?;
    let public_outputs = json!({
        "program_hash": format!("0x{:x}", verification.program_hash),
        "output": verification
            .output
            .iter()
            .map(|fe| format!("0x{fe:x}"))
            .collect::<Vec<_>>(),
    });
    write_json(&out_dir.join("public_outputs.json"), &public_outputs)?;
    let io_dur = t.elapsed();

    let total_dur = total.elapsed();

    // 6. Report + summary.json.
    println!();
    println!("phase        wall");
    println!("compile      {}", fmt_dur(compile_dur));
    println!(
        "run/witness  {}  ({} steps)",
        fmt_dur(run_dur), steps
    );
    println!("prove        {}", fmt_dur(prove_dur));
    println!("verify       {}  OK", fmt_dur(verify_dur));
    println!("serialize    {}", fmt_dur(io_dur));
    println!("total        {}", fmt_dur(total_dur));
    println!();
    println!("builtins (padded segment counts):");
    for (name, count) in sorted_counts(&resources.builtin_instance_counter) {
        println!("  {name:<16} {count}");
    }
    let public_output_str = public_outputs["output"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    println!("program hash : {}", public_outputs["program_hash"].as_str().unwrap_or_default());
    println!("public output: [{public_output_str}]");
    println!("proof        : {} ({})", proof_path.display(), human_size(&proof_path));

    let summary = json!({
        "tool": "prove-hand",
        "program": program,
        "corelib": corelib,
        "scale": scale.label(),
        "inputs": args.inputs,
        "verified": true,
        "artifacts": {
            "executable": "executable.json",
            "proof": proof_path.file_name().and_then(|n| n.to_str()).unwrap_or("proof.json"),
            "public_outputs": "public_outputs.json",
        },
        "timings_ms": {
            "compile": compile_dur.as_millis() as u64,
            "run_witness": run_dur.as_millis() as u64,
            "prove": prove_dur.as_millis() as u64,
            "verify": verify_dur.as_millis() as u64,
            "serialize": io_dur.as_millis() as u64,
            "total": total_dur.as_millis() as u64,
        },
        "execution": {
            "steps": steps,
            "unique_pcs": resources.verify_instruction,
            "builtin_instance_counter": resources.builtin_instance_counter,
            "opcodes_instance_counter": resources.opcodes_instance_counter,
        },
        "public": public_outputs,
        "prover_params": serde_json::to_value(&params)?,
    });
    let summary_path = out_dir.join("summary.json");
    write_json(&summary_path, &summary)?;
    println!("summary      : {}", summary_path.display());
    Ok(())
}

fn check_only(args: &Args, out_dir: &Path) -> Result<()> {
    let proof_path = args.proof.clone().unwrap_or_else(|| {
        out_dir.join(proof_file_name(&args.proof_format))
    });
    if !proof_path.exists() {
        bail!(
            "no proof at {} — run the pipeline first (or pass --proof)",
            proof_path.display()
        );
    }
    println!("prove-hand: check-only {}", proof_path.display());
    let t = Instant::now();
    let proof = deserialize_proof_from_file::<Blake2sMerkleHasher>(
        &proof_path,
        args.proof_format.clone(),
    )
        .with_context(|| format!("read proof {}", proof_path.display()))?;
    let load_dur = t.elapsed();

    let t = Instant::now();
    let public_memory = proof.claim.public_data.public_memory.clone();
    let verification = get_verification_output(&public_memory);
    let result = verify_cairo::<Blake2sMerkleChannel>(proof);
    let verify_dur = t.elapsed();
    match &result {
        Ok(()) => println!("verify       {}  OK", fmt_dur(verify_dur)),
        Err(e) => println!("verify       {}  FAILED: {e}", fmt_dur(verify_dur)),
    }
    println!("load         {}", fmt_dur(load_dur));
    println!("program hash : 0x{:x}", verification.program_hash);
    println!(
        "public output: [{}]",
        verification.output.iter().map(|fe| format!("0x{fe:x}")).collect::<Vec<_>>().join(", ")
    );
    result.context("proof verification FAILED")
}

#[derive(Clone, Copy, Debug)]
enum Scale {
    Small,
    Medium,
    Full,
    /// Custom bench with N_CHALLENGES = n (N_EC and PAYLOAD_LEN derived).
    Custom(usize),
}

impl Scale {
    fn label(&self) -> String {
        match self {
            Scale::Small => "small".into(),
            Scale::Medium => "medium".into(),
            Scale::Full => "full".into(),
            Scale::Custom(n) => format!("custom{n}"),
        }
    }
}

fn parse_scale(s: &str) -> Result<Scale> {
    match s {
        "small" => Ok(Scale::Small),
        "medium" => Ok(Scale::Medium),
        "full" => Ok(Scale::Full),
        s if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() => {
            let n: usize = s.parse().context("--scale <number> must be a challenge count")?;
            if n == 0 {
                bail!("--scale <number> must be >= 1");
            }
            Ok(Scale::Custom(n))
        }
        _ => bail!("invalid --scale '{s}': expected small | medium | full | <challenge count>"),
    }
}

fn resolve_program(args: &Args, root: &Path, scale: &Scale, out_dir: &Path) -> Result<PathBuf> {
    if let Some(program) = &args.program {
        if matches!(scale, Scale::Custom(_)) {
            bail!("--program and a numeric --scale are mutually exclusive");
        }
        return Ok(program.clone());
    }
    match scale {
        Scale::Custom(n) => {
            // Same ratios as the shipped benches (small: 22/148/70, full: 220/1480/700).
            let n_ec = (n * 148).div_ceil(22);
            let payload_len = (n * 70).div_ceil(22);
            let src = BENCH_TEMPLATE
                .replace("__N_CHALLENGES__", &n.to_string())
                .replace("__N_EC__", &n_ec.to_string())
                .replace("__PAYLOAD_LEN__", &payload_len.to_string());
            let path = out_dir.join("hand_verify_bench_custom.cairo");
            fs::write(&path, src).with_context(|| format!("write {}", path.display()))?;
            Ok(path)
        }
        named => Ok(root
            .join(BENCH_DIR_REL)
            .join(format!("hand_verify_bench_{}.cairo", named.label()))),
    }
}

/// Mirrors the 96-bit-security defaults of `stwo-cairo-prover::create_and_serialize_proof`.
fn default_params() -> ProverParameters {
    ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: 0,
        fri_config: FriConfig {
            pow_bits: 26,
            log_last_layer_degree_bound: 0,
            log_blowup_factor: 1,
            n_queries: 70,
            fold_step: 1,
        },
        preprocessed_trace: PreProcessedTraceVariant::Canonical,
        store_polynomials_coefficients: false,
        include_all_preprocessed_columns: false,
        opt_n_id_to_big_components: None,
        lifting_size_policy: LiftingSizePolicy::Auto,
    }
}

fn load_params(args: &Args) -> Result<ProverParameters> {
    match &args.params {
        Some(path) => {
            let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
            Ok(serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?)
        }
        None => Ok(default_params()),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("proving-tool must live inside the project")
        .to_path_buf()
}

fn proof_file_name(format: &ProofFormat) -> String {
    match format {
        ProofFormat::Binary | ProofFormat::ExtendedBinary => "proof.bin".into(),
        _ => "proof.json".into(),
    }
}

fn format_name(format: &ProofFormat) -> &'static str {
    match format {
        ProofFormat::Json => "json",
        ProofFormat::CairoSerde => "cairo_serde",
        ProofFormat::Binary => "binary",
        ProofFormat::ExtendedBinary => "extended_binary",
    }
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut f = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut bytes = serde_json::to_string_pretty(value)?.into_bytes();
    bytes.push(b'\n');
    f.write_all(&bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn sorted_counts(map: &std::collections::HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut entries: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    entries
}

fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 { format!("{secs:.2} s") } else { format!("{} ms", d.as_millis()) }
}

fn human_size(path: &Path) -> String {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return "n/a".into(),
    };
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return "n/a".into();
    }
    let bytes = buf.len() as f64;
    if bytes >= 1e6 { format!("{:.1} MB", bytes / 1e6) } else { format!("{:.0} KB", bytes / 1e3) }
}
