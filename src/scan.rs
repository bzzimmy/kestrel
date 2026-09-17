use std::cell::RefCell;
use std::fs::{self, DirEntry, File};
use std::io::{self, ErrorKind, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use memchr::memchr_iter;
use rayon::{Scope, ThreadPoolBuildError, ThreadPoolBuilder};
use thiserror::Error;

use crate::matcher::{Encoding, Matcher, Scratch};

/// One fixed buffer per thread; memory is `threads × CHUNK_SIZE` regardless of file size.
const CHUNK_SIZE: usize = 1 << 20;
/// Overlap between chunks in units of `Matcher::reach`: one for the match,
/// one for its hit, one for the confirmation window. Each chunk owns matches
/// starting in `[reach, len - 2 * reach)`, so every match is reported once.
const OVERLAP_REACHES: usize = 3;
/// Scanning is read-latency bound, so the default pool oversubscribes cores.
const THREADS_PER_CORE: usize = 4;
const MIN_THREADS: usize = 8;

thread_local! {
    static READ_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static SCRATCH: RefCell<Scratch> = const { RefCell::new(Scratch::new()) };
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
    /// Worker threads; `None` uses `default_threads`.
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
    /// Set when `secret` was decoded from an encoded run at `start`.
    pub encoding: Option<Encoding>,
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
    /// Folds one directory's tally in with a single atomic per counter.
    fn add(&self, tally: &Stats) {
        self.files_scanned
            .fetch_add(tally.files_scanned, Ordering::Relaxed);
        self.files_skipped
            .fetch_add(tally.files_skipped, Ordering::Relaxed);
        self.files_failed
            .fetch_add(tally.files_failed, Ordering::Relaxed);
        self.dirs_failed
            .fetch_add(tally.dirs_failed, Ordering::Relaxed);
        self.bytes_scanned
            .fetch_add(tally.bytes_scanned, Ordering::Relaxed);
        self.findings.fetch_add(tally.findings, Ordering::Relaxed);
    }

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
    chunk_size: usize,
    reach: usize,
}

/// Maps chunk-relative match offsets to absolute file offsets and 1-based
/// lines, counting newlines incrementally between reported matches.
struct Cursor {
    /// File offset of the current chunk's first byte.
    base: usize,
    /// Line number at `counted_to`.
    line: usize,
    /// Chunk-relative offset up to which newlines have been counted.
    counted_to: usize,
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
    scan_dir_chunked(root, matcher, options, CHUNK_SIZE, sink)
}

fn scan_dir_chunked<F>(
    root: &Path,
    matcher: &Matcher,
    options: &Options,
    chunk_size: usize,
    sink: F,
) -> Result<Stats, ScanError>
where
    F: Fn(&Finding<'_>) + Sync,
{
    let reach = matcher.reach();
    let scanner = Scanner {
        matcher,
        max_file_size: options.max_file_size,
        sink: &sink,
        counters: Counters::default(),
        chunk_size: chunk_size.max(2 * OVERLAP_REACHES * reach),
        reach,
    };
    let pool = ThreadPoolBuilder::new()
        .num_threads(options.threads.unwrap_or_else(default_threads))
        .build()?;
    pool.scope(|scope| scanner.walk(scope, root))
        .map_err(|source| ScanError::Root {
            path: root.to_path_buf(),
            source,
        })?;
    Ok(scanner.counters.snapshot())
}

impl<F: Fn(&Finding<'_>) + Sync> Scanner<'_, F> {
    /// Files are scanned inline; only subdirectories become tasks.
    fn walk<'s>(&'s self, scope: &Scope<'s>, dir: &Path) -> io::Result<()> {
        let entries = fs::read_dir(dir)?;
        let mut tally = Stats::default();
        for entry in entries {
            match entry {
                Ok(entry) => self.visit(scope, &entry, &mut tally),
                Err(err) => {
                    log_dir_failure(dir, &err);
                    tally.dirs_failed += 1;
                }
            }
        }
        self.counters.add(&tally);
        Ok(())
    }

    fn visit<'s>(&'s self, scope: &Scope<'s>, entry: &DirEntry, tally: &mut Stats) {
        let path = entry.path();
        let outcome = match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {
                scope.spawn(move |scope| {
                    if let Err(err) = self.walk(scope, &path) {
                        log_dir_failure(&path, &err);
                        self.counters.dirs_failed.fetch_add(1, Ordering::Relaxed);
                    }
                });
                return;
            }
            Ok(file_type) if file_type.is_file() => self.scan_file(&path, tally),
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        };
        if let Err(err) = outcome {
            eprintln!("kestrel: failed to scan {}: {err}", path.display());
            tally.files_failed += 1;
        }
    }

    fn scan_file(&self, path: &Path, tally: &mut Stats) -> io::Result<()> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if self.max_file_size.is_some_and(|max| len > max) {
            tally.files_skipped += 1;
            return Ok(());
        }
        let findings = READ_BUF.with_borrow_mut(|buf| {
            if buf.len() < self.chunk_size {
                *buf = vec![0; self.chunk_size];
            }
            self.scan_chunks(path, &file, len, &mut buf[..self.chunk_size])
        })?;
        tally.files_scanned += 1;
        tally.bytes_scanned += len;
        tally.findings += findings;
        Ok(())
    }

    /// Streams `file` through `buf`, carrying the overlap tail into the next chunk.
    fn scan_chunks(&self, path: &Path, file: &File, len: u64, buf: &mut [u8]) -> io::Result<u64> {
        let overlap = OVERLAP_REACHES * self.reach;
        let mut cursor = Cursor::new();
        let mut remaining = len;
        let mut carried = 0;
        let mut count = 0;
        loop {
            let want = usize::try_from(remaining)
                .ok()
                .and_then(|remaining| remaining.checked_add(carried))
                .map_or(buf.len(), |total| total.min(buf.len()));
            let read = fill(file, &mut buf[carried..want])?;
            remaining = remaining.saturating_sub(read as u64);
            let chunk = &buf[..carried + read];
            let last = remaining == 0 || chunk.len() < want;
            let owned = Range {
                start: if carried == 0 { 0 } else { self.reach },
                end: if last {
                    chunk.len()
                } else {
                    chunk.len() - overlap + self.reach
                },
            };
            count += self.scan_chunk(path, chunk, owned, &mut cursor);
            if last {
                return Ok(count);
            }
            cursor.next_chunk(chunk, overlap);
            buf.copy_within(want - overlap..want, 0);
            carried = overlap;
        }
    }

    /// Scans one chunk, reporting only matches whose start lies in `owned`.
    fn scan_chunk(
        &self,
        path: &Path,
        chunk: &[u8],
        owned: Range<usize>,
        cursor: &mut Cursor,
    ) -> u64 {
        let mut count = 0;
        SCRATCH.with_borrow_mut(|scratch| {
            self.matcher.scan(chunk, scratch, |m| {
                if !owned.contains(&m.start) {
                    return;
                }
                (self.sink)(&Finding {
                    path,
                    rule_id: m.rule_id,
                    start: cursor.base + m.start,
                    line: cursor.line_at(chunk, m.start),
                    secret: m.secret,
                    encoding: m.encoding,
                });
                count += 1;
            });
        });
        count
    }
}

/// `THREADS_PER_CORE` per available core, at least `MIN_THREADS`.
fn default_threads() -> usize {
    thread::available_parallelism()
        .map_or(MIN_THREADS, |cores| cores.get() * THREADS_PER_CORE)
        .max(MIN_THREADS)
}

fn log_dir_failure(path: &Path, err: &io::Error) {
    eprintln!(
        "kestrel: failed to read directory {}: {err}",
        path.display()
    );
}

impl Cursor {
    fn new() -> Self {
        Self {
            base: 0,
            line: 1,
            counted_to: 0,
        }
    }

    /// Encoded runs may start before the previous match, so counting can go backwards.
    fn line_at(&mut self, chunk: &[u8], offset: usize) -> usize {
        if offset >= self.counted_to {
            self.line += memchr_iter(b'\n', &chunk[self.counted_to..offset]).count();
        } else {
            self.line -= memchr_iter(b'\n', &chunk[offset..self.counted_to]).count();
        }
        self.counted_to = offset;
        self.line
    }

    /// Moves to the next chunk, which starts `overlap` bytes before the end
    /// of `chunk`.
    fn next_chunk(&mut self, chunk: &[u8], overlap: usize) {
        let next = chunk.len() - overlap;
        self.line_at(chunk, next);
        self.base += next;
        self.counted_to = 0;
    }
}

/// Reads until `buf` is full or the file ends, returning the bytes read.
fn fill(mut file: &File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}
#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use memchr::memchr_iter;
    use tempfile::TempDir;
    use test_case::test_case;

    use super::{CHUNK_SIZE, Finding, Options, ScanError, Stats, scan_dir, scan_dir_chunked};
    use crate::matcher::Matcher;
    use crate::rules::Rule;

    /// The test rule's reach is 20 bytes, so chunks overlap by 60.
    const TEST_CHUNK: usize = 256;
    const FILLER_LINE: &[u8] = b".........\n";
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
        line: usize,
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
                line: finding.line,
                secret: finding.secret.to_vec(),
            }
        }
    }

    fn found_at(path: &str, start: usize, line: usize) -> Owned {
        Owned {
            path: PathBuf::from(path),
            rule_id: RULE_ID,
            start,
            line,
            secret: SECRET.to_vec(),
        }
    }

    fn found(path: &str, start: usize) -> Owned {
        found_at(path, start, 1)
    }

    fn scan(root: &Path, options: &Options) -> (Stats, Vec<Owned>) {
        scan_chunked(root, options, CHUNK_SIZE)
    }

    #[expect(
        clippy::expect_used,
        reason = "failures here are test setup bugs, not behaviour under test"
    )]
    fn scan_chunked(root: &Path, options: &Options, chunk_size: usize) -> (Stats, Vec<Owned>) {
        let matcher = Matcher::new(&[RULE]).expect("test rule must compile");
        let findings = Mutex::new(Vec::new());
        let stats = scan_dir_chunked(root, &matcher, options, chunk_size, |finding| {
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

    /// Ten-byte filler lines with `SECRET` written over them at each position.
    fn planted(len: usize, positions: &[usize]) -> Vec<u8> {
        let mut contents: Vec<u8> = FILLER_LINE.iter().copied().cycle().take(len).collect();
        for &at in positions {
            contents[at..at + SECRET.len()].copy_from_slice(SECRET);
        }
        contents
    }

    fn line_of(contents: &[u8], at: usize) -> usize {
        1 + memchr_iter(b'\n', &contents[..at]).count()
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
    fn file_larger_than_default_chunk_is_scanned() {
        let dir = temp();
        let mut contents = vec![b'x'; CHUNK_SIZE];
        contents.extend_from_slice(LINE);
        write(dir.path(), "big.js", &contents);
        let (stats, findings) = scan(dir.path(), &Options::default());
        assert_eq!(findings, [found("big.js", CHUNK_SIZE + LINE_OFFSET)]);
        assert_eq!(stats, scanned(1, contents.len(), 1));
    }

    #[test_case(300, &[252] ; "straddles_first_chunk_end")]
    #[test_case(300, &[248] ; "ends_exactly_at_first_chunk_end")]
    #[test_case(300, &[256] ; "starts_exactly_at_first_chunk_end")]
    #[test_case(300, &[220] ; "inside_overlap_region")]
    #[test_case(300, &[196] ; "at_second_chunk_start")]
    #[test_case(300, &[190] ; "straddles_second_chunk_start")]
    #[test_case(300, &[292] ; "at_file_end")]
    #[test_case(2000, &[0, 100, 196, 252, 700, 1234, 1500, 1992] ; "many_chunks")]
    #[test_case(2000, &[1000, 1010, 1020, 1030, 1040, 1050, 1060, 1070, 1080] ; "dense_across_a_boundary")]
    fn chunked_scan_reports_each_secret_once_at_absolute_position(len: usize, positions: &[usize]) {
        let dir = temp();
        let contents = planted(len, positions);
        write(dir.path(), "f", &contents);
        let (stats, findings) = scan_chunked(dir.path(), &Options::default(), TEST_CHUNK);
        let expected: Vec<Owned> = positions
            .iter()
            .map(|&at| found_at("f", at, line_of(&contents, at)))
            .collect();
        assert_eq!(findings, expected);
        assert_eq!(stats, scanned(1, len, positions.len() as u64));
    }

    #[test]
    fn every_boundary_offset_is_reported_once() {
        let dir = temp();
        let mut contents = Vec::new();
        let mut positions = Vec::new();
        for at in (0..3 * TEST_CHUNK).step_by(SECRET.len() + 1) {
            positions.push(at);
            contents.extend_from_slice(SECRET);
            contents.push(if at % 3 == 0 { b'\n' } else { b' ' });
        }
        write(dir.path(), "f", &contents);
        let (stats, findings) = scan_chunked(dir.path(), &Options::default(), TEST_CHUNK);
        let expected: Vec<Owned> = positions
            .iter()
            .map(|&at| found_at("f", at, line_of(&contents, at)))
            .collect();
        assert_eq!(findings, expected);
        assert_eq!(stats.findings, positions.len() as u64);
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
