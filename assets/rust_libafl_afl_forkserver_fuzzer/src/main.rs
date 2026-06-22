use std::{env, fs, path::PathBuf, process, time::Duration};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{forkserver::ForkserverExecutor, HasObservers, StdChildArgs},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, tokens_mutations, HavocScheduledMutator, Tokens},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasSolutions, StdState},
    HasMetadata,
};
use libafl_bolts::{
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSliceMut, StdTargetArgs, Truncate,
};

const MAP_SIZE: usize = 65536;

#[derive(Debug)]
struct Opt {
    in_dir: PathBuf,
    out_dir: PathBuf,
    iterations: usize,
    timeout_ms: u64,
    token_files: Vec<PathBuf>,
    debug_child: bool,
    target_cmd: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: rust_libafl_afl_forkserver_fuzzer --in DIR --out DIR [--iterations N] [--timeout-ms N] [--token-file DICT]... [--debug-child] -- <afl-instrumented-target> [args...] [@@]"
    );
    process::exit(2);
}

fn parse_args() -> Opt {
    let mut in_dir = None;
    let mut out_dir = None;
    let mut iterations = 1000usize;
    let mut timeout_ms = 1000u64;
    let mut token_files = Vec::new();
    let mut debug_child = false;
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
            "--debug-child" => debug_child = true,
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
        debug_child,
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

    let executable = opt.target_cmd[0].clone();
    let target_args = opt.target_cmd[1..].to_vec();
    let corpus_dirs = vec![opt.in_dir.clone()];

    let mut shmem_provider = UnixShMemProvider::new().expect("create shmem provider");
    let mut shmem = shmem_provider
        .new_shmem(MAP_SIZE)
        .expect("create coverage shmem");
    unsafe {
        shmem
            .write_to_env("__AFL_SHM_ID")
            .expect("write AFL shmem env");
    }
    let shmem_buf = shmem.as_slice_mut();

    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };
    let observer_handle = edges_observer.handle();
    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );
    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("crash_map", &edges_observer)
    );

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
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut tokens = load_tokens(&opt.token_files);
    let file_token_count = tokens.len();
    let mut executor = ForkserverExecutor::builder()
        .program(executable)
        .debug_child(opt.debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(target_args)
        .coverage_map_size(MAP_SIZE)
        .timeout(Duration::from_millis(opt.timeout_ms))
        .build(tuple_list!(time_observer, edges_observer))
        .expect("build forkserver executor");

    if let Some(dynamic_map_size) = executor.coverage_map_size() {
        executor.observers_mut()[&observer_handle]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| panic!("load initial corpus from {corpus_dirs:?}: {err:?}"));
    }
    let total_token_count = tokens.len();
    state.add_metadata(tokens);

    println!(
        "imported {} initial inputs; loaded {} file tokens and {} total tokens",
        state.corpus().count(),
        file_token_count,
        total_token_count
    );

    let mutator =
        HavocScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);
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
