use std::{env, fs, path::PathBuf, process, time::Duration};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::{command::CommandExecutor, StdChildArgs},
    feedbacks::{ConstFeedback, CrashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, tokens_mutations, HavocScheduledMutator, Tokens},
    schedulers::{QueueScheduler, Scheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasSolutions, StdState},
    HasMetadata,
};
use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, Merge},
    StdTargetArgs,
};

#[derive(Debug)]
struct Opt {
    in_dir: PathBuf,
    out_dir: PathBuf,
    iterations: usize,
    timeout_ms: u64,
    token_files: Vec<PathBuf>,
    target_cmd: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: rust_libafl_cli_command_fuzzer --in DIR --out DIR [--iterations N] [--timeout-ms N] [--token-file DICT]... -- <target> [args...] [@@]"
    );
    process::exit(2);
}

fn parse_args() -> Opt {
    let mut in_dir = None;
    let mut out_dir = None;
    let mut iterations = 1000usize;
    let mut timeout_ms = 1000u64;
    let mut token_files = Vec::new();
    let mut target_cmd = Vec::new();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--in" => in_dir = args.next().map(PathBuf::from),
            "--out" => out_dir = args.next().map(PathBuf::from),
            "--iterations" => {
                iterations = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--timeout-ms" => {
                timeout_ms = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--token-file" => {
                token_files.push(args.next().map(PathBuf::from).unwrap_or_else(|| usage()))
            }
            "--" => {
                target_cmd.extend(args);
                break;
            }
            _ => usage(),
        }
    }

    let Some(in_dir) = in_dir else { usage() };
    let Some(out_dir) = out_dir else { usage() };
    if target_cmd.is_empty() {
        usage();
    }

    Opt {
        in_dir,
        out_dir,
        iterations,
        timeout_ms,
        token_files,
        target_cmd,
    }
}

fn decode_dict_token(raw: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            return Err("trailing backslash in token".to_string());
        }
        match bytes[i] {
            b'x' => {
                if i + 2 >= bytes.len() {
                    return Err("short hex escape in token".to_string());
                }
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|e| e.to_string())?;
                let value = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                out.push(value);
                i += 3;
            }
            b'n' => {
                out.push(b'\n');
                i += 1;
            }
            b'r' => {
                out.push(b'\r');
                i += 1;
            }
            b't' => {
                out.push(b'\t');
                i += 1;
            }
            b'\\' => {
                out.push(b'\\');
                i += 1;
            }
            b'"' => {
                out.push(b'"');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn token_from_line(line: &str) -> Result<Option<Vec<u8>>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    if let Some(start) = trimmed.find('"') {
        let Some(end) = trimmed.rfind('"') else {
            return Err(format!("unterminated dictionary token: {trimmed}"));
        };
        if end <= start {
            return Err(format!("empty or malformed dictionary token: {trimmed}"));
        }
        let decoded = decode_dict_token(&trimmed[start + 1..end])?;
        if decoded.is_empty() {
            return Ok(None);
        }
        return Ok(Some(decoded));
    }
    Ok(Some(trimmed.as_bytes().to_vec()))
}

fn load_tokens(paths: &[PathBuf]) -> Tokens {
    let mut tokens = Tokens::new();
    for path in paths {
        let content = fs::read_to_string(path).unwrap_or_else(|err| {
            panic!("read token file {}: {err}", path.display());
        });
        for (idx, line) in content.lines().enumerate() {
            match token_from_line(line) {
                Ok(Some(token)) => {
                    tokens.add_token(&token);
                }
                Ok(None) => {}
                Err(err) => panic!("parse token file {}:{}: {err}", path.display(), idx + 1),
            }
        }
    }
    tokens
}

fn main() {
    let opt = parse_args();
    let queue_dir = opt.out_dir.join("queue");
    let crashes_dir = opt.out_dir.join("crashes");
    fs::create_dir_all(&queue_dir).expect("create queue dir");
    fs::create_dir_all(&crashes_dir).expect("create crashes dir");

    // No coverage observer is available for this generic command wrapper.
    // Keep only the initial corpus and objective findings; do not pretend every
    // mutated input is interesting.
    let mut feedback = ConstFeedback::new(false);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(crashes_dir).expect("create crash corpus"),
        &mut feedback,
        &mut objective,
    )
    .expect("create state");

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);
    let mut scheduler = QueueScheduler::new();
    let mut imported = 0usize;
    for entry in fs::read_dir(&opt.in_dir).expect("read seed dir") {
        let path = entry.expect("read seed entry").path();
        if !path.is_file() {
            continue;
        }
        let data = fs::read(&path).expect("read seed file");
        if data.is_empty() {
            continue;
        }
        let id = state
            .corpus_mut()
            .add(Testcase::new(BytesInput::new(data)))
            .expect("add seed to corpus");
        <QueueScheduler as Scheduler<BytesInput, _>>::on_add(&mut scheduler, &mut state, id)
            .expect("schedule seed");
        imported += 1;
    }
    if imported == 0 {
        panic!("no non-empty seed files in {}", opt.in_dir.display());
    }
    let tokens = load_tokens(&opt.token_files);
    let token_count = tokens.len();
    state.add_metadata(tokens);

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = CommandExecutor::builder()
        .parse_afl_cmdline(opt.target_cmd)
        .timeout(Duration::from_millis(opt.timeout_ms))
        .build(())
        .expect("build command executor");

    println!("imported {imported} initial inputs; loaded {token_count} dictionary tokens");

    let mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    for _ in 0..opt.iterations {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("fuzz one");
    }

    println!(
        "done iterations={} corpus={} crashes={}",
        opt.iterations,
        state.corpus().count(),
        state.solutions().count()
    );
}
