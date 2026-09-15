mod matcher;
mod rules;

use std::env;
use std::fs;
use std::io::{self, Read};

use anyhow::{Context, Result};

use crate::matcher::Matcher;
use crate::rules::RULES;

fn main() -> Result<()> {
    let matcher = Matcher::new(RULES)?;
    let buf = if let Some(path) = env::args().nth(1) {
        fs::read(&path).with_context(|| format!("failed to read {path}"))?
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read stdin")?;
        buf
    };
    for m in matcher.scan(&buf) {
        println!(
            "{}\t{}\t{}",
            m.rule_id,
            m.start,
            String::from_utf8_lossy(&buf[m.start..m.end])
        );
    }
    Ok(())
}
