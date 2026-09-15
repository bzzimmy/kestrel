mod matcher;
mod output;
mod rules;
mod scan;

use std::io::{self, BufWriter};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;

use crate::matcher::Matcher;
use crate::output::JsonLines;
use crate::rules::RULES;
use crate::scan::{Options, scan_dir};

const BYTES_PER_MB: f64 = 1e6;
const STDOUT_BUFFER: usize = 1 << 16;

/// Ultra-lightweight secret scanner. Walks a directory tree and emits one
/// JSON object per finding to stdout.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Directory to scan recursively
    dir: PathBuf,

    /// Worker threads (default: available cores)
    #[arg(short, long, value_name = "N")]
    threads: Option<usize>,

    /// Skip files larger than this many bytes
    #[arg(long, value_name = "BYTES")]
    max_file_size: Option<u64>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let matcher = Matcher::new(RULES).context("failed to compile rules")?;
    let options = Options {
        max_file_size: cli.max_file_size,
        threads: cli.threads,
    };
    let output = JsonLines::new(BufWriter::with_capacity(STDOUT_BUFFER, io::stdout()));
    let started = Instant::now();
    let stats = scan_dir(&cli.dir, &matcher, &options, |finding| {
        output.write(finding);
    })
    .with_context(|| format!("failed to scan {}", cli.dir.display()))?;
    let elapsed = started.elapsed();
    output.finish().context("failed to flush findings")?;
    #[expect(
        clippy::cast_precision_loss,
        reason = "throughput is a log figure; byte counts never approach 2^52"
    )]
    let throughput = stats.bytes_scanned as f64 / BYTES_PER_MB / elapsed.as_secs_f64();
    eprintln!(
        "scan complete files={} skipped={} failed={} dirs_failed={} bytes={} findings={} duration={elapsed:.2?} throughput={throughput:.1}MB/s",
        stats.files_scanned,
        stats.files_skipped,
        stats.files_failed,
        stats.dirs_failed,
        stats.bytes_scanned,
        stats.findings,
    );
    Ok(())
}
