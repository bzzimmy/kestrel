use std::cell::RefCell;
use std::fs::{self, DirEntry, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use memchr::memchr_iter;
use memmap2::MmapOptions;
use rayon::{Scope, ThreadPoolBuildError, ThreadPoolBuilder};
use thiserror::Error;

use crate::matcher::Matcher;

/// Files at least this large are mmap'd; smaller ones are read into a reused
/// per-thread buffer, which beats mmap/munmap overhead for the small files
/// that dominate npm packages.
const MMAP_MIN_SIZE: usize = 1 << 20;

thread_local! {
    static READ_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("failed to read directory {path}")]
    Root {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to build thread pool")]
    ThreadPool(#[from] ThreadPoolBuildError),
}

#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Files larger than this are skipped and counted in `files_skipped`.
    pub max_file_size: Option<u64>,
    /// Worker threads; `None` lets rayon pick (available cores).
    pub threads: Option<usize>,
}

/// A confirmed secret; borrows from the file buffer, so consume it inside
/// the sink or copy what you need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding<'a> {
    pub path: &'a Path,
    pub rule_id: &'static str,
    pub start: usize,
    /// 1-based line containing `start`.
    pub line: usize,
    pub secret: &'a [u8],
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub files_scanned: u64,
    /// Files over `max_file_size`.
    pub files_skipped: u64,
    pub files_failed: u64,
    pub dirs_failed: u64,
    pub bytes_scanned: u64,
    pub findings: u64,
}

#[derive(Default)]
struct Counters {
    files_scanned: AtomicU64,
    files_skipped: AtomicU64,
    files_failed: AtomicU64,
    dirs_failed: AtomicU64,
    bytes_scanned: AtomicU64,
    findings: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> Stats {
        Stats {
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            files_skipped: self.files_skipped.load(Ordering::Relaxed),
            files_failed: self.files_failed.load(Ordering::Relaxed),
            dirs_failed: self.dirs_failed.load(Ordering::Relaxed),
            bytes_scanned: self.bytes_scanned.load(Ordering::Relaxed),
            findings: self.findings.load(Ordering::Relaxed),
        }
    }
}

struct Scanner<'a, F> {
    matcher: &'a Matcher,
    max_file_size: Option<u64>,
    sink: &'a F,
    counters: Counters,
}

/// Scans every regular file under `root`, calling `sink` from worker threads
/// for each finding. Symlinks are never followed. Per-file and per-directory
/// errors are logged to stderr and counted; only an unreadable `root` or a
/// thread pool failure aborts.
pub fn scan_dir<F>(
    root: &Path,
    matcher: &Matcher,
    options: &Options,
    sink: F,
) -> Result<Stats, ScanError>
where
    F: Fn(&Finding<'_>) + Sync,
{
    let scanner = Scanner {
        matcher,
        max_file_size: options.max_file_size,
        sink: &sink,
        counters: Counters::default(),
    };
    let pool = ThreadPoolBuilder::new()
        .num_threads(options.threads.unwrap_or_default())
        .build()?;
    pool.scope(|scope| scanner.walk(scope, root))
        .map_err(|source| ScanError::Root {
            path: root.to_path_buf(),
            source,
        })?;
    Ok(scanner.counters.snapshot())
}

impl<F: Fn(&Finding<'_>) + Sync> Scanner<'_, F> {
    fn walk<'s>(&'s self, scope: &Scope<'s>, dir: &Path) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            match entry {
                Ok(entry) => scope.spawn(move |scope| self.visit(scope, &entry)),
                Err(err) => self.dir_failed(dir, &err),
            }
        }
        Ok(())
    }

    fn visit<'s>(&'s self, scope: &Scope<'s>, entry: &DirEntry) {
        let path = entry.path();
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {
                if let Err(err) = self.walk(scope, &path) {
                    self.dir_failed(&path, &err);
                }
            }
            Ok(file_type) if file_type.is_file() => {
                if let Err(err) = self.scan_file(&path) {
                    self.file_failed(&path, &err);
                }
            }
            Ok(_) => {}
            Err(err) => self.file_failed(&path, &err),
        }
    }

    fn scan_file(&self, path: &Path) -> io::Result<()> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if self.max_file_size.is_some_and(|max| len > max) {
            self.counters.files_skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let findings = match usize::try_from(len) {
            Ok(0) => 0,
            Ok(len) if len < MMAP_MIN_SIZE => READ_BUF.with_borrow_mut(|buf| {
                buf.resize(len, 0);
                (&file).read_exact(buf)?;
                Ok::<_, io::Error>(self.scan_buf(path, buf))
            })?,
            _ => {
                // SAFETY: the file is opened read-only and the mapping is
                // private to this call; concurrent modification of a file
                // being scanned is outside the supported contract.
                let mmap = unsafe { MmapOptions::new().populate().map(&file)? };
                self.scan_buf(path, &mmap)
            }
        };
        self.counters.files_scanned.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes_scanned
            .fetch_add(len, Ordering::Relaxed);
        self.counters
            .findings
            .fetch_add(findings, Ordering::Relaxed);
        Ok(())
    }

    fn scan_buf(&self, path: &Path, buf: &[u8]) -> u64 {
        let mut count = 0;
        let mut line = 1;
        let mut counted_to = 0;
        for m in self.matcher.scan(buf) {
            if m.start < counted_to {
                line = 1;
                counted_to = 0;
            }
            line += memchr_iter(b'\n', &buf[counted_to..m.start]).count();
            counted_to = m.start;
            (self.sink)(&Finding {
                path,
                rule_id: m.rule_id,
                start: m.start,
                line,
                secret: &buf[m.start..m.end],
            });
            count += 1;
        }
        count
    }

    fn file_failed(&self, path: &Path, err: &io::Error) {
        eprintln!("kestrel: failed to scan {}: {err}", path.display());
        self.counters.files_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn dir_failed(&self, path: &Path, err: &io::Error) {
        eprintln!(
            "kestrel: failed to read directory {}: {err}",
            path.display()
        );
        self.counters.dirs_failed.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use tempfile::TempDir;
    use test_case::test_case;

    use super::{Finding, MMAP_MIN_SIZE, Options, ScanError, Stats, scan_dir};
    use crate::matcher::Matcher;
    use crate::rules::Rule;

    const RULE_ID: &str = "tok";
    const RULE: Rule = Rule {
        id: RULE_ID,
        anchors: &["tok_"],
        pattern: r"\btok_[0-9]{4}\b",
        verify: None,
    };
    const SECRET: &[u8] = b"tok_1234";
    const LINE: &[u8] = b"token: tok_1234\n";
    const LINE_OFFSET: usize = 7;
    const CLEAN: &[u8] = b"nothing here\n";

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Owned {
        path: PathBuf,
        rule_id: &'static str,
        start: usize,
        secret: Vec<u8>,
    }

    impl Owned {
        fn of(root: &Path, finding: &Finding<'_>) -> Self {
            Self {
                path: finding
                    .path
                    .strip_prefix(root)
                    .map_or_else(|_| finding.path.to_path_buf(), Path::to_path_buf),
                rule_id: finding.rule_id,
                start: finding.start,
                secret: finding.secret.to_vec(),
            }
        }
    }

    fn found(path: &str, start: usize) -> Owned {
        Owned {
            path: PathBuf::from(path),
            rule_id: RULE_ID,
            start,
            secret: SECRET.to_vec(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "failures here are test setup bugs, not behaviour under test"
    )]
    fn scan(root: &Path, options: &Options) -> (Stats, Vec<Owned>) {
        let matcher = Matcher::new(&[RULE]).expect("test rule must compile");
        let findings = Mutex::new(Vec::new());
        let stats = scan_dir(root, &matcher, options, |finding| {
            findings
                .lock()
                .expect("sink mutex poisoned")
                .push(Owned::of(root, finding));
        })
        .expect("scan must succeed");
        let mut findings = findings.into_inner().expect("sink mutex poisoned");
        findings.sort();
        (stats, findings)
    }

    #[expect(
        clippy::expect_used,
        reason = "failures here are test setup bugs, not behaviour under test"
    )]
    fn write(root: &Path, rel: &str, contents: &[u8]) -> PathBuf {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&path, contents).expect("write fixture");
        path
    }

    #[expect(clippy::expect_used, reason = "temp dir creation is test setup")]
    fn temp() -> TempDir {
        TempDir::new().expect("create temp dir")
    }

    fn scanned(files_scanned: u64, bytes_scanned: usize, findings: u64) -> Stats {
        Stats {
            files_scanned,
            bytes_scanned: bytes_scanned as u64,
            findings,
            ..Stats::default()
        }
    }

    /// Returns false when permissions do not restrict us (e.g. running as root).
    #[cfg(unix)]
    #[expect(clippy::expect_used, reason = "chmod is test setup")]
    fn make_unreadable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).expect("chmod");
        if path.is_dir() {
            fs::read_dir(path).is_err()
        } else {
            File::open(path).is_err()
        }
    }

    #[test_case(None ; "default_threads")]
    #[test_case(Some(1) ; "single_thread")]
    #[test_case(Some(4) ; "four_threads")]
    fn finds_secrets_in_nested_dirs(threads: Option<usize>) {
        let dir = temp();
        write(dir.path(), "top.js", LINE);
        write(dir.path(), "a/b/c/deep.json", LINE);
        write(dir.path(), "a/clean.md", CLEAN);
        let options = Options {
            threads,
            ..Options::default()
        };
        let (stats, findings) = scan(dir.path(), &options);
        assert_eq!(
            findings,
            [
                found("a/b/c/deep.json", LINE_OFFSET),
                found("top.js", LINE_OFFSET)
            ]
        );
        assert_eq!(stats, scanned(3, 2 * LINE.len() + CLEAN.len(), 2));
    }

    #[test]
    fn reports_offset_and_secret_bytes() {
        let dir = temp();
        write(dir.path(), "f", b"\xff\xfe tok_1234 tok_5678 tok_12");
        let (stats, findings) = scan(dir.path(), &Options::default());
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].start, 3);
        assert_eq!(findings[0].secret, SECRET);
        assert_eq!(findings[1].start, 12);
        assert_eq!(findings[1].secret, b"tok_5678");
        assert_eq!(stats.findings, 2);
    }

    #[test]
    fn empty_file_is_scanned_without_findings() {
        let dir = temp();
        write(dir.path(), "empty", b"");
        let (stats, findings) = scan(dir.path(), &Options::default());
        assert_eq!(findings, []);
        assert_eq!(stats, scanned(1, 0, 0));
    }

    #[test_case(Some(LINE.len() as u64 - 1), 0, 1 ; "over_limit_is_skipped")]
    #[test_case(Some(LINE.len() as u64), 1, 0 ; "at_limit_is_scanned")]
    #[test_case(None, 1, 0 ; "no_limit")]
    fn max_file_size(limit: Option<u64>, scanned: u64, skipped: u64) {
        let dir = temp();
        write(dir.path(), "f", LINE);
        let options = Options {
            max_file_size: limit,
            ..Options::default()
        };
        let (stats, findings) = scan(dir.path(), &options);
        assert_eq!(findings.len(), usize::try_from(scanned).unwrap_or_default());
        assert_eq!(stats.files_scanned, scanned);
        assert_eq!(stats.files_skipped, skipped);
        assert_eq!(stats.bytes_scanned, scanned * LINE.len() as u64);
    }

    #[test]
    fn large_file_takes_mmap_path() {
        let dir = temp();
        let mut contents = vec![b'x'; MMAP_MIN_SIZE];
        contents.extend_from_slice(LINE);
        write(dir.path(), "big.js", &contents);
        let (stats, findings) = scan(dir.path(), &Options::default());
        assert_eq!(findings, [found("big.js", MMAP_MIN_SIZE + LINE_OFFSET)]);
        assert_eq!(stats, scanned(1, contents.len(), 1));
    }

    #[expect(
        clippy::expect_used,
        reason = "a rule that fails to compile is a test bug"
    )]
    #[test]
    fn missing_root_is_an_error() {
        let dir = temp();
        let matcher = Matcher::new(&[RULE]).expect("test rule must compile");
        let missing = dir.path().join("missing");
        let result = scan_dir(&missing, &matcher, &Options::default(), |_| {});
        assert!(matches!(result, Err(ScanError::Root { path, .. }) if path == missing));
    }

    #[cfg(unix)]
    #[expect(clippy::expect_used, reason = "symlink creation is test setup")]
    #[test]
    fn symlinks_are_skipped() {
        use std::os::unix::fs::symlink;
        let dir = temp();
        let target = write(dir.path(), "real/secret.js", LINE);
        symlink(&target, dir.path().join("link.js")).expect("file symlink");
        symlink(dir.path().join("real"), dir.path().join("linkdir")).expect("dir symlink");
        symlink(dir.path().join("nowhere"), dir.path().join("dangling")).expect("dangling symlink");
        let (stats, findings) = scan(dir.path(), &Options::default());
        assert_eq!(findings, [found("real/secret.js", LINE_OFFSET)]);
        assert_eq!(stats, scanned(1, LINE.len(), 1));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_counted_and_scan_continues() {
        let dir = temp();
        let locked = write(dir.path(), "locked.js", LINE);
        write(dir.path(), "open.js", LINE);
        if !make_unreadable(&locked) {
            return;
        }
        let (stats, findings) = scan(dir.path(), &Options::default());
        assert_eq!(findings, [found("open.js", LINE_OFFSET)]);
        assert_eq!(
            stats,
            Stats {
                files_failed: 1,
                ..scanned(1, LINE.len(), 1)
            }
        );
    }

    #[cfg(unix)]
    #[expect(clippy::expect_used, reason = "restoring permissions is test cleanup")]
    #[test]
    fn unreadable_dir_is_counted_and_scan_continues() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp();
        write(dir.path(), "locked/secret.js", LINE);
        write(dir.path(), "open.js", LINE);
        let locked = dir.path().join("locked");
        if !make_unreadable(&locked) {
            return;
        }
        let (stats, findings) = scan(dir.path(), &Options::default());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore chmod");
        assert_eq!(findings, [found("open.js", LINE_OFFSET)]);
        assert_eq!(
            stats,
            Stats {
                dirs_failed: 1,
                ..scanned(1, LINE.len(), 1)
            }
        );
    }
}
