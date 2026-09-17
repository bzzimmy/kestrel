use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::ParserBuilder;
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Hir, Look};
use thiserror::Error;

use crate::base64::{decode_into, encoded_anchors, is_base64_byte};
use crate::rules::Rule;

/// Window on each side of an anchor hit for patterns without a bounded
/// maximum length; must cover the longest secret (PEM blocks).
const UNBOUNDED_WINDOW: usize = 32 * 1024;
/// Extra byte past the window so a trailing `\b` sees the next character.
const BOUNDARY_SLACK: usize = 1;
/// Base64 characters per 3 decoded bytes.
const ENCODED_GROUP: usize = 4;
const DECODED_GROUP: usize = 3;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("rule `{rule}` has no anchors")]
    NoAnchors { rule: &'static str },
    #[error("rule `{rule}` has an invalid pattern")]
    Pattern {
        rule: &'static str,
        #[source]
        source: regex::Error,
    },
    #[error("rule `{rule}` pattern matches the empty string")]
    EmptyPattern { rule: &'static str },
    #[error("failed to build anchor automaton")]
    Automaton(#[from] aho_corasick::BuildError),
}

/// A confirmed secret. `start..end` is its span in the scanned buffer; for a
/// base64 hit that span is the encoded run and `secret` is the decoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match<'a> {
    pub rule_id: &'static str,
    pub start: usize,
    pub end: usize,
    pub secret: &'a [u8],
    pub encoding: Option<Encoding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Base64,
}

pub struct Matcher {
    automaton: AhoCorasick,
    rules: Vec<CompiledRule>,
    patterns: Vec<Pattern>,
}

/// Per-thread working memory reused across `Matcher::scan` calls; secrets may borrow from it.
#[derive(Debug, Default)]
pub struct Scratch {
    decoded: Vec<u8>,
    last_start: Vec<Option<usize>>,
}

impl Scratch {
    pub const fn new() -> Self {
        Self {
            decoded: Vec::new(),
            last_start: Vec::new(),
        }
    }
}

/// What an automaton pattern stands for: a rule's anchor as-is, or that
/// anchor as it appears inside base64 text at a given byte alignment.
struct Pattern {
    rule: usize,
    encoded: Option<Alignment>,
}

#[derive(Clone, Copy)]
struct Alignment {
    /// Byte offset of the anchor within its first 3-byte group.
    offset: usize,
    /// Encoded characters between that group's start and the literal.
    skip: usize,
}

struct CompiledRule {
    id: &'static str,
    regex: Regex,
    window: usize,
    /// True when the pattern starts with `\b` and every anchor is a literal
    /// prefix of it, so a hit whose preceding byte is in the same word class
    /// as its first byte can be rejected without running the regex.
    boundary_prefix: bool,
    verify: Option<fn(&[u8]) -> bool>,
}

impl Matcher {
    pub fn new<'r>(rules: impl IntoIterator<Item = &'r Rule>) -> Result<Self, BuildError> {
        let rules: Vec<&Rule> = rules.into_iter().collect();
        let compiled = rules
            .iter()
            .map(|rule| CompiledRule::new(rule))
            .collect::<Result<Vec<_>, _>>()?;
        let mut literals: Vec<Vec<u8>> = Vec::new();
        let mut patterns = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            for anchor in rule.anchors {
                literals.push(anchor.as_bytes().to_vec());
                patterns.push(Pattern {
                    rule: index,
                    encoded: None,
                });
                for encoded in encoded_anchors(anchor.as_bytes()) {
                    literals.push(encoded.literal);
                    patterns.push(Pattern {
                        rule: index,
                        encoded: Some(Alignment {
                            offset: encoded.alignment,
                            skip: encoded.skip,
                        }),
                    });
                }
            }
        }
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .kind(Some(AhoCorasickKind::DFA))
            .build(&literals)?;
        Ok(Self {
            automaton,
            rules: compiled,
            patterns,
        })
    }

    /// Calls `sink` with every confirmed secret in `buf`, in anchor-hit order.
    /// Hits are leftmost-longest, so `xoxb-` inside `xoxe.xoxb-` only fires on its own.
    pub fn scan(&self, buf: &[u8], scratch: &mut Scratch, mut sink: impl FnMut(&Match<'_>)) {
        scratch.last_start.clear();
        scratch.last_start.resize(self.rules.len(), None);
        for hit in self.automaton.find_iter(buf) {
            let pattern = &self.patterns[hit.pattern().as_usize()];
            let rule = &self.rules[pattern.rule];
            let found = match pattern.encoded {
                None => rule.confirm(buf, hit.start()).map(|(start, end)| Match {
                    rule_id: rule.id,
                    start,
                    end,
                    secret: &buf[start..end],
                    encoding: None,
                }),
                Some(alignment) => {
                    rule.confirm_encoded(buf, hit.start(), alignment, &mut scratch.decoded)
                }
            };
            let Some(found) = found else {
                continue;
            };
            if scratch.last_start[pattern.rule] == Some(found.start) {
                continue;
            }
            scratch.last_start[pattern.rule] = Some(found.start);
            sink(&found);
        }
    }

    /// Max distance from an anchor hit to any byte confirmation inspects or reports.
    pub fn reach(&self) -> usize {
        self.rules
            .iter()
            .map(CompiledRule::reach)
            .max()
            .unwrap_or_default()
    }
}

impl CompiledRule {
    fn new(rule: &Rule) -> Result<Self, BuildError> {
        if rule.anchors.is_empty() {
            return Err(BuildError::NoAnchors { rule: rule.id });
        }
        let regex = RegexBuilder::new(rule.pattern)
            .unicode(false)
            .build()
            .map_err(|source| BuildError::Pattern {
                rule: rule.id,
                source,
            })?;
        if regex.is_match(b"") {
            return Err(BuildError::EmptyPattern { rule: rule.id });
        }
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(rule.pattern)
            .ok();
        let window = hir
            .as_ref()
            .and_then(|hir| hir.properties().maximum_len())
            .unwrap_or(UNBOUNDED_WINDOW);
        Ok(Self {
            id: rule.id,
            regex,
            window,
            boundary_prefix: hir
                .is_some_and(|hir| anchors_are_boundary_prefixes(&hir, rule.anchors)),
            verify: rule.verify,
        })
    }

    /// Runs the confirming regex on a window around `hit` and returns the
    /// secret's byte range in `buf` if the leftmost match covering the hit
    /// passes the verify hook. The secret is capture group 1 when the
    /// pattern has one (keyword-gated rules), else the whole match. The
    /// window is the pattern's maximum match length on each side, so a
    /// match covering the hit can never be cut off.
    fn confirm(&self, buf: &[u8], hit: usize) -> Option<(usize, usize)> {
        if hit >= buf.len() {
            return None;
        }
        if self.boundary_prefix && hit > 0 && is_word_byte(buf[hit - 1]) == is_word_byte(buf[hit]) {
            return None;
        }
        let lo = hit.saturating_sub(self.window);
        let hi = buf.len().min(hit + self.window + BOUNDARY_SLACK);
        let window = &buf[lo..hi];
        let hit = hit - lo;
        let whole = self
            .regex
            .find_iter(window)
            .find(|m| m.end() > hit)
            .filter(|m| m.start() <= hit)?;
        let secret = if self.regex.captures_len() > 1 {
            self.regex.captures_at(window, whole.start())?.get(1)?
        } else {
            whole
        };
        self.verify
            .is_none_or(|verify| verify(secret.as_bytes()))
            .then(|| (lo + secret.start(), lo + secret.end()))
    }

    /// Decodes the base64 run around an encoded-anchor hit into `scratch`
    /// and confirms the rule on the decoded bytes. The run is cut to the
    /// rule's window on each side of the hit and kept aligned to 4-character
    /// groups so the anchor decodes at a known offset.
    fn confirm_encoded<'s>(
        &self,
        buf: &[u8],
        hit: usize,
        alignment: Alignment,
        scratch: &'s mut Vec<u8>,
    ) -> Option<Match<'s>> {
        let limit = self.encoded_limit();
        let group_start = hit.checked_sub(alignment.skip)?;
        let run_lo = (group_start.saturating_sub(limit)..group_start)
            .rev()
            .take_while(|&i| is_base64_byte(buf[i]))
            .last()
            .unwrap_or(group_start);
        let lo = group_start - (group_start - run_lo) / ENCODED_GROUP * ENCODED_GROUP;
        let hi = (hit..buf.len().min(hit + limit))
            .find(|&i| !is_base64_byte(buf[i]) && buf[i] != b'=')
            .unwrap_or(buf.len().min(hit + limit));
        decode_into(&buf[lo..hi], scratch);
        let decoded_hit = (group_start - lo) / ENCODED_GROUP * DECODED_GROUP + alignment.offset;
        let (start, end) = self.confirm(scratch, decoded_hit)?;
        Some(Match {
            rule_id: self.id,
            start: lo,
            end: hi,
            secret: &scratch[start..end],
            encoding: Some(Encoding::Base64),
        })
    }

    /// Base64 characters taken on each side of an encoded hit: the window in
    /// encoded form plus one group of alignment slack.
    fn encoded_limit(&self) -> usize {
        self.window.div_ceil(DECODED_GROUP) * ENCODED_GROUP + ENCODED_GROUP
    }

    fn reach(&self) -> usize {
        (self.window + BOUNDARY_SLACK).max(self.encoded_limit() + ENCODED_GROUP)
    }
}

/// True if the pattern must start at a word boundary and each anchor is one
/// of its literal prefixes (or extends one), i.e. the anchor hit is where the
/// match would start.
fn anchors_are_boundary_prefixes(hir: &Hir, anchors: &[&str]) -> bool {
    if !hir.properties().look_set_prefix().contains(Look::WordAscii) {
        return false;
    }
    let prefixes = Extractor::new().kind(ExtractKind::Prefix).extract(hir);
    let Some(literals) = prefixes.literals() else {
        return false;
    };
    anchors.iter().all(|anchor| {
        literals.iter().any(|literal| {
            let (short, long) = if literal.len() <= anchor.len() {
                (literal.as_bytes(), anchor.as_bytes())
            } else {
                (anchor.as_bytes(), literal.as_bytes())
            };
            !short.is_empty() && long.starts_with(short)
        })
    })
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::{BuildError, CompiledRule, Encoding, Matcher, Scratch, UNBOUNDED_WINDOW};
    use crate::rules::Rule;

    const PREFIX_ID: &str = "prefix";
    const LONG_PREFIX_ID: &str = "long_prefix";
    const KEYWORD_ID: &str = "keyword";
    const DOUBLE_ID: &str = "double";
    const VERIFIED_ID: &str = "verified";

    const PREFIX: Rule = Rule {
        id: PREFIX_ID,
        anchors: &["tok_"],
        pattern: r"\btok_[0-9]{4}\b",
        verify: None,
    };
    const UNBOUNDED_PREFIX: Rule = Rule {
        pattern: r"tok_[0-9]{4}",
        ..PREFIX
    };
    const LONG_PREFIX: Rule = Rule {
        id: LONG_PREFIX_ID,
        anchors: &["live_tok_"],
        pattern: r"live_tok_[0-9]{4}",
        verify: None,
    };
    const KEYWORD: Rule = Rule {
        id: KEYWORD_ID,
        anchors: &["secret"],
        pattern: r"secret\s{0,4}=\s{0,4}([a-z]{8})\b",
        verify: None,
    };
    const DOUBLE: Rule = Rule {
        id: DOUBLE_ID,
        anchors: &["BEGIN", "END"],
        pattern: r"BEGIN [a-z]+ END",
        verify: None,
    };
    const VERIFIED: Rule = Rule {
        id: VERIFIED_ID,
        anchors: &["num_"],
        pattern: r"num_[0-9]{4}",
        verify: Some(all_even),
    };

    fn all_even(secret: &[u8]) -> bool {
        secret[4..].iter().all(|digit| (digit - b'0') % 2 == 0)
    }

    fn scan(rules: &[Rule], buf: &[u8]) -> Vec<(&'static str, usize, usize)> {
        found(rules, buf)
            .into_iter()
            .map(|f| (f.rule_id, f.start, f.end))
            .collect()
    }

    /// Owned copy of a match, since secrets may borrow the decode scratch.
    #[derive(Debug, PartialEq, Eq)]
    struct Found {
        rule_id: &'static str,
        start: usize,
        end: usize,
        secret: Vec<u8>,
        encoding: Option<Encoding>,
    }

    #[expect(
        clippy::expect_used,
        reason = "a rule that fails to compile is a test bug"
    )]
    fn found(rules: &[Rule], buf: &[u8]) -> Vec<Found> {
        let matcher = Matcher::new(rules).expect("test rules must compile");
        let mut out = Vec::new();
        matcher.scan(buf, &mut Scratch::new(), |m| {
            out.push(Found {
                rule_id: m.rule_id,
                start: m.start,
                end: m.end,
                secret: m.secret.to_vec(),
                encoding: m.encoding,
            });
        });
        out
    }

    fn m(rule_id: &'static str, start: usize, end: usize) -> (&'static str, usize, usize) {
        (rule_id, start, end)
    }

    #[test_case(b"tok_1234", &[m(PREFIX_ID, 0, 8)] ; "anchor_at_buffer_start")]
    #[test_case(b"x = tok_1234", &[m(PREFIX_ID, 4, 12)] ; "anchor_at_buffer_end")]
    #[test_case(b"a tok_1234 b", &[m(PREFIX_ID, 2, 10)] ; "anchor_mid_buffer")]
    #[test_case(b"\xff\xfetok_1234\xff", &[m(PREFIX_ID, 2, 10)] ; "non_utf8_context")]
    #[test_case(b"tok_1234 tok_5678", &[m(PREFIX_ID, 0, 8), m(PREFIX_ID, 9, 17)] ; "two_tokens")]
    #[test_case(b"tok_123", &[] ; "too_short")]
    #[test_case(b"tok_12345", &[] ; "too_long")]
    #[test_case(b"tok_12a4", &[] ; "wrong_charset")]
    #[test_case(b"tak_1234", &[] ; "near_miss_prefix")]
    #[test_case(b"xtok_1234", &[] ; "no_leading_boundary")]
    fn prefix_rule(buf: &[u8], expected: &[(&str, usize, usize)]) {
        assert_eq!(scan(&[PREFIX], buf), expected);
    }

    #[test_case(b"secret=abcdefgh", &[m(KEYWORD_ID, 7, 15)] ; "no_gap")]
    #[test_case(b"secret  =  abcdefgh", &[m(KEYWORD_ID, 11, 19)] ; "small_gap")]
    #[test_case(b"secret      =abcdefgh", &[] ; "gap_too_large")]
    #[test_case(b"secret=abcdefg", &[] ; "value_too_short")]
    #[test_case(b"secret=ABCDEFGH", &[] ; "value_wrong_charset")]
    #[test_case(b"secret=\nsecret=abcdefgh", &[m(KEYWORD_ID, 15, 23)] ; "second_keyword_confirms")]
    fn keyword_rule_reports_value_only(buf: &[u8], expected: &[(&str, usize, usize)]) {
        assert_eq!(scan(&[KEYWORD], buf), expected);
    }

    #[test_case(b"BEGIN key END", &[m(DOUBLE_ID, 0, 13)] ; "both_anchors_one_match")]
    #[test_case(b"BEGIN key END BEGIN other END", &[m(DOUBLE_ID, 0, 13), m(DOUBLE_ID, 14, 29)] ; "adjacent_blocks")]
    #[test_case(b"END BEGIN", &[] ; "anchors_without_structure")]
    fn double_anchored_rule_deduplicates(buf: &[u8], expected: &[(&str, usize, usize)]) {
        assert_eq!(scan(&[DOUBLE], buf), expected);
    }

    #[test_case(b"num_2468", &[m(VERIFIED_ID, 0, 8)] ; "verify_accepts")]
    #[test_case(b"num_2461", &[] ; "verify_rejects")]
    #[test_case(b"num_2461 num_0000", &[m(VERIFIED_ID, 9, 17)] ; "verify_rejects_only_failing")]
    fn verify_hook(buf: &[u8], expected: &[(&str, usize, usize)]) {
        assert_eq!(scan(&[VERIFIED], buf), expected);
    }

    #[test_case(b"live_tok_1234", &[m(LONG_PREFIX_ID, 0, 13)] ; "embedded_anchor_is_not_a_hit")]
    #[test_case(b"live_tok_1234 tok_5678", &[m(LONG_PREFIX_ID, 0, 13), m(PREFIX_ID, 14, 22)] ; "shorter_anchor_still_hits_elsewhere")]
    fn overlapping_anchors_resolve_to_leftmost_longest(
        buf: &[u8],
        expected: &[(&str, usize, usize)],
    ) {
        assert_eq!(scan(&[UNBOUNDED_PREFIX, LONG_PREFIX], buf), expected);
    }

    #[test]
    fn rules_interleave_in_hit_order() {
        let buf = b"tok_1234 secret=abcdefgh tok_5678";
        assert_eq!(
            scan(&[PREFIX, KEYWORD], buf),
            [
                m(PREFIX_ID, 0, 8),
                m(KEYWORD_ID, 16, 24),
                m(PREFIX_ID, 25, 33)
            ]
        );
    }

    #[test]
    fn unbounded_secret_longer_than_window_is_not_reported() {
        let mut buf = b"BEGIN ".to_vec();
        buf.extend(std::iter::repeat_n(b'a', UNBOUNDED_WINDOW));
        buf.extend_from_slice(b" END");
        assert_eq!(scan(&[DOUBLE], &buf), []);
    }

    #[test]
    fn unbounded_secret_within_window_is_reported() {
        let body = UNBOUNDED_WINDOW - "BEGIN ".len() - " END".len();
        let mut buf = b"BEGIN ".to_vec();
        buf.extend(std::iter::repeat_n(b'a', body));
        buf.extend_from_slice(b" END");
        assert_eq!(scan(&[DOUBLE], &buf), [m(DOUBLE_ID, 0, UNBOUNDED_WINDOW)]);
    }

    #[test]
    fn bounded_secret_far_from_buffer_edges_is_reported() {
        let padding = vec![b'a'; UNBOUNDED_WINDOW];
        let buf = [padding.as_slice(), b" tok_1234 ", padding.as_slice()].concat();
        let start = UNBOUNDED_WINDOW + 1;
        assert_eq!(scan(&[PREFIX], &buf), [m(PREFIX_ID, start, start + 8)]);
    }

    #[test]
    fn rejects_rule_without_anchors() {
        let rule = Rule {
            anchors: &[],
            ..PREFIX
        };
        assert!(matches!(
            Matcher::new(&[rule]),
            Err(BuildError::NoAnchors { rule: PREFIX_ID })
        ));
    }

    #[test]
    fn rejects_invalid_pattern() {
        let rule = Rule {
            pattern: r"tok_(",
            ..PREFIX
        };
        assert!(matches!(
            Matcher::new(&[rule]),
            Err(BuildError::Pattern {
                rule: PREFIX_ID,
                ..
            })
        ));
    }

    #[test]
    fn rejects_pattern_matching_empty() {
        let rule = Rule {
            pattern: r"(?:tok_)?",
            ..PREFIX
        };
        assert!(matches!(
            Matcher::new(&[rule]),
            Err(BuildError::EmptyPattern { rule: PREFIX_ID })
        ));
    }

    #[test_case(&PREFIX, true ; "boundary_then_literal")]
    #[test_case(&UNBOUNDED_PREFIX, false ; "no_boundary")]
    #[test_case(&KEYWORD, false ; "keyword_without_boundary")]
    #[test_case(&Rule { pattern: r"\b(?:tok_|live_tok_)[0-9]{4}", ..PREFIX }, true ; "anchor_among_alternates")]
    #[test_case(&Rule { anchors: &["_tok_"], pattern: r"\b[a-z]{4}_tok_[0-9]{4}", ..PREFIX }, false ; "anchor_mid_pattern")]
    fn boundary_prefix_is_detected(rule: &Rule, expected: bool) {
        assert_eq!(
            CompiledRule::new(rule)
                .map(|compiled| compiled.boundary_prefix)
                .ok(),
            Some(expected)
        );
    }

    #[test_case(b"xtok_1234" ; "preceded_by_letter")]
    #[test_case(b"_tok_1234" ; "preceded_by_underscore")]
    #[test_case(b"9tok_1234" ; "preceded_by_digit")]
    fn boundary_prefix_rejects_hit_inside_word(buf: &[u8]) {
        assert_eq!(scan(&[PREFIX], buf), []);
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut group = [0u8; 3];
            group[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            for i in 0..4 {
                out.push(if i <= chunk.len() {
                    ALPHABET[((bits >> (18 - 6 * i)) & 0x3F) as usize] as char
                } else {
                    '='
                });
            }
        }
        out
    }

    #[test_case(b"tok_1234" ; "aligned")]
    #[test_case(b"x tok_1234" ; "offset_one")]
    #[test_case(b"xy tok_1234" ; "offset_two")]
    #[test_case(b"{\"token\":\"tok_1234\",\"other\":\"value\"}" ; "inside_json")]
    fn decodes_base64_at_every_alignment(plain: &[u8]) {
        let encoded = base64(plain);
        let buf = format!("KEY={encoded}\n");
        let hits = found(&[PREFIX], buf.as_bytes());
        assert_eq!(hits.len(), 1, "{buf}");
        assert_eq!(hits[0].secret, b"tok_1234");
        assert_eq!(hits[0].encoding, Some(Encoding::Base64));
        assert!(encoded.contains(&buf[hits[0].start..hits[0].end]));
    }

    #[test]
    fn decodes_url_safe_alphabet() {
        let encoded = base64(b"\xfb\xff tok_1234")
            .replace('+', "-")
            .replace('/', "_");
        let hits = found(&[PREFIX], encoded.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].secret, b"tok_1234");
    }

    #[test]
    fn decoded_secret_still_needs_confirmation() {
        let buf = base64(b"tok_12 not a token");
        assert!(found(&[PREFIX], buf.as_bytes()).is_empty());
    }

    #[test]
    fn plain_and_encoded_occurrences_are_both_reported() {
        let buf = format!("tok_1234 {}", base64(b"tok_5678"));
        let hits = found(&[PREFIX], buf.as_bytes());
        let secrets: Vec<&[u8]> = hits.iter().map(|h| h.secret.as_slice()).collect();
        assert_eq!(secrets, [&b"tok_1234"[..], b"tok_5678"]);
        assert_eq!(hits[1].encoding, Some(Encoding::Base64));
    }

    #[test]
    fn encoded_run_is_cut_to_the_window() {
        let mut plain = vec![b'a'; 4096];
        plain.extend_from_slice(b" tok_1234 ");
        plain.extend(vec![b'b'; 4096]);
        let buf = base64(&plain);
        let hits = found(&[PREFIX], buf.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].secret, b"tok_1234");
        assert!(
            hits[0].end - hits[0].start < 256,
            "run span {}",
            hits[0].end - hits[0].start
        );
    }

    #[test]
    fn truncated_encoded_run_does_not_panic() {
        let encoded = base64(b"xy tok_1234");
        let buf = &encoded.as_bytes()[..encoded.len() - 4];
        assert!(found(&[PREFIX], buf).is_empty());
    }
}
