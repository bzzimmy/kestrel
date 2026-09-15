use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::sync::{Mutex, PoisonError};

use serde::Serialize;

use crate::scan::Finding;

/// Characters kept on each side of a redacted secret.
const REDACT_EDGE: usize = 4;
const ELLIPSIS: &str = "...";

/// Writes one JSON object per finding, newline-terminated. Safe to call from
/// scan worker threads; write failures are logged to stderr so one bad write
/// never aborts a batch.
pub struct JsonLines<W> {
    writer: Mutex<W>,
}

#[derive(Serialize)]
struct Record<'a> {
    path: &'a str,
    offset: usize,
    rule: &'static str,
    secret: &'a str,
    redacted: Redacted<'a>,
}

struct Redacted<'a>(&'a str);

impl<W: Write> JsonLines<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }

    pub fn write(&self, finding: &Finding<'_>) {
        let path = finding.path.to_string_lossy();
        let secret = String::from_utf8_lossy(finding.secret);
        let record = Record {
            path: &path,
            offset: finding.start,
            rule: finding.rule_id,
            secret: &secret,
            redacted: Redacted(&secret),
        };
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(err) = serde_json::to_writer(&mut *writer, &record)
            .map_err(io::Error::from)
            .and_then(|()| writer.write_all(b"\n"))
        {
            eprintln!("kestrel: failed to write finding: {err}");
        }
    }

    /// Flushes and returns the underlying writer.
    pub fn finish(self) -> io::Result<W> {
        let mut writer = self
            .writer
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        writer.flush()?;
        Ok(writer)
    }
}

impl Display for Redacted<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let secret = self.0;
        if secret.chars().count() <= 2 * REDACT_EDGE {
            return f.write_str(ELLIPSIS);
        }
        let head: usize = secret.chars().take(REDACT_EDGE).map(char::len_utf8).sum();
        let tail: usize = secret
            .chars()
            .rev()
            .take(REDACT_EDGE)
            .map(char::len_utf8)
            .sum();
        write!(
            f,
            "{}{ELLIPSIS}{}",
            &secret[..head],
            &secret[secret.len() - tail..]
        )
    }
}

impl Serialize for Redacted<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::path::Path;

    use serde_json::{Value, json};
    use test_case::test_case;

    use super::{ELLIPSIS, JsonLines, Redacted};
    use crate::scan::Finding;

    const RULE_ID: &str = "tok";
    const WRITE_ERROR: &str = "disk full";

    struct Failing;

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other(WRITE_ERROR))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn finding<'a>(path: &'a Path, start: usize, secret: &'a [u8]) -> Finding<'a> {
        Finding {
            path,
            rule_id: RULE_ID,
            start,
            secret,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "failures here are test setup bugs, not behaviour under test"
    )]
    fn lines(findings: &[Finding<'_>]) -> Vec<Value> {
        let output = JsonLines::new(Vec::new());
        for finding in findings {
            output.write(finding);
        }
        let bytes = output.finish().expect("flush into vec cannot fail");
        let text = String::from_utf8(bytes).expect("output is utf-8");
        assert!(text.ends_with('\n'), "output must be newline-terminated");
        text.lines()
            .map(|line| serde_json::from_str(line).expect("each line is a json object"))
            .collect()
    }

    #[test_case("tok_1234567890", "tok_...7890" ; "ascii")]
    #[test_case("tok_12345", "tok_...2345" ; "one_over_threshold")]
    #[test_case("tok_1234", ELLIPSIS ; "at_threshold_fully_masked")]
    #[test_case("", ELLIPSIS ; "empty")]
    #[test_case("ééééXXXXéééé", "éééé...éééé" ; "multibyte_edges")]
    fn redacts_to_edges(secret: &str, expected: &str) {
        assert_eq!(Redacted(secret).to_string(), expected);
    }

    #[test]
    fn writes_one_json_object_per_finding() {
        let path = Path::new("pkg@1.0.0/index.js");
        let records = lines(&[
            finding(path, 7, b"tok_1234567890"),
            finding(path, 42, b"tok_0987654321"),
        ]);
        assert_eq!(
            records,
            [
                json!({
                    "path": "pkg@1.0.0/index.js",
                    "offset": 7,
                    "rule": RULE_ID,
                    "secret": "tok_1234567890",
                    "redacted": "tok_...7890",
                }),
                json!({
                    "path": "pkg@1.0.0/index.js",
                    "offset": 42,
                    "rule": RULE_ID,
                    "secret": "tok_0987654321",
                    "redacted": "tok_...4321",
                }),
            ]
        );
    }

    #[test]
    fn escapes_json_and_replaces_invalid_utf8() {
        let path = Path::new("dir/with \"quotes\"\nand newline.js");
        let records = lines(&[finding(path, 0, b"tok_\xff\"\\12345678")]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["path"], "dir/with \"quotes\"\nand newline.js");
        assert_eq!(records[0]["secret"], "tok_\u{fffd}\"\\12345678");
        assert_eq!(records[0]["redacted"], "tok_...5678");
    }

    #[test]
    fn write_failure_does_not_panic() {
        let output = JsonLines::new(Failing);
        output.write(&finding(Path::new("f"), 0, b"tok_1234567890"));
        assert!(output.finish().is_ok());
    }
}
