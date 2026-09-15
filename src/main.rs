mod matcher;
mod rules;
mod scan;

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::matcher::Matcher;
use crate::rules::RULES;
use crate::scan::{Finding, Options, scan_dir};

const USAGE: &str = "usage: kestrel <dir>";
const BYTES_PER_MB: f64 = 1e6;

fn main() -> Result<()> {
    let root = env::args_os().nth(1).context(USAGE)?;
    let matcher = Matcher::new(RULES)?;
    let started = Instant::now();
    let stats = scan_dir(Path::new(&root), &matcher, &Options::default(), emit)?;
    let elapsed = started.elapsed();
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

fn emit(finding: &Finding<'_>) {
    if let Err(err) = writeln!(
        io::stdout(),
        "{}\t{}\t{}\t{}",
        finding.path.display(),
        finding.rule_id,
        finding.start,
        String::from_utf8_lossy(finding.secret)
    ) {
        eprintln!("kestrel: failed to write finding: {err}");
    }
}
