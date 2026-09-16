use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::Parser;
use thiserror::Error;

use crate::rules::Rule;

/// Window on each side of an anchor hit for patterns without a bounded
/// maximum length; must cover the longest secret (PEM blocks).
const UNBOUNDED_WINDOW: usize = 32 * 1024;
/// Extra byte past the window so a trailing `\b` sees the next character.
const BOUNDARY_SLACK: usize = 1;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule_id: &'static str,
    pub start: usize,
    pub end: usize,
}

pub struct Matcher {
    automaton: AhoCorasick,
    rules: Vec<CompiledRule>,
    rule_of_pattern: Vec<usize>,
}

struct CompiledRule {
    id: &'static str,
    regex: Regex,
    window: usize,
    verify: Option<fn(&[u8]) -> bool>,
}

impl Matcher {
    pub fn new<'r>(rules: impl IntoIterator<Item = &'r Rule>) -> Result<Self, BuildError> {
        let rules: Vec<&Rule> = rules.into_iter().collect();
        let compiled = rules
            .iter()
            .map(|rule| CompiledRule::new(rule))
            .collect::<Result<Vec<_>, _>>()?;
        let rule_of_pattern = rules
            .iter()
            .enumerate()
            .flat_map(|(index, rule)| rule.anchors.iter().map(move |_| index))
            .collect();
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .kind(Some(AhoCorasickKind::DFA))
            .build(rules.iter().flat_map(|rule| rule.anchors))?;
        Ok(Self {
            automaton,
            rules: compiled,
            rule_of_pattern,
        })
    }

    /// Yields every confirmed secret in `buf` as byte offsets, in anchor-hit
    /// order. The same `(rule, start)` is never yielded twice. Anchor hits
    /// are non-overlapping and leftmost-longest, so an anchor embedded in a
    /// longer one (`xoxb-` inside `xoxe.xoxb-`) only fires on its own.
    pub fn scan<'a>(&'a self, buf: &'a [u8]) -> impl Iterator<Item = Match> + 'a {
        let mut last_start = vec![None; self.rules.len()];
        self.automaton.find_iter(buf).filter_map(move |hit| {
            let index = self.rule_of_pattern[hit.pattern().as_usize()];
            let rule = &self.rules[index];
            let (start, end) = rule.confirm(buf, hit.start())?;
            if last_start[index] == Some(start) {
                return None;
            }
            last_start[index] = Some(start);
            Some(Match {
                rule_id: rule.id,
                start,
                end,
            })
        })
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
        let window = Parser::new()
            .parse(rule.pattern)
            .ok()
            .and_then(|hir| hir.properties().maximum_len())
            .unwrap_or(UNBOUNDED_WINDOW);
        Ok(Self {
            id: rule.id,
            regex,
            window,
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
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::{BuildError, Match, Matcher, UNBOUNDED_WINDOW};
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

    #[expect(
        clippy::expect_used,
        reason = "a rule that fails to compile is a test bug"
    )]
    fn scan(rules: &[Rule], buf: &[u8]) -> Vec<Match> {
        Matcher::new(rules)
            .expect("test rules must compile")
            .scan(buf)
            .collect()
    }

    fn m(rule_id: &'static str, start: usize, end: usize) -> Match {
        Match {
            rule_id,
            start,
            end,
        }
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
    fn prefix_rule(buf: &[u8], expected: &[Match]) {
        assert_eq!(scan(&[PREFIX], buf), expected);
    }

    #[test_case(b"secret=abcdefgh", &[m(KEYWORD_ID, 7, 15)] ; "no_gap")]
    #[test_case(b"secret  =  abcdefgh", &[m(KEYWORD_ID, 11, 19)] ; "small_gap")]
    #[test_case(b"secret      =abcdefgh", &[] ; "gap_too_large")]
    #[test_case(b"secret=abcdefg", &[] ; "value_too_short")]
    #[test_case(b"secret=ABCDEFGH", &[] ; "value_wrong_charset")]
    #[test_case(b"secret=\nsecret=abcdefgh", &[m(KEYWORD_ID, 15, 23)] ; "second_keyword_confirms")]
    fn keyword_rule_reports_value_only(buf: &[u8], expected: &[Match]) {
        assert_eq!(scan(&[KEYWORD], buf), expected);
    }

    #[test_case(b"BEGIN key END", &[m(DOUBLE_ID, 0, 13)] ; "both_anchors_one_match")]
    #[test_case(b"BEGIN key END BEGIN other END", &[m(DOUBLE_ID, 0, 13), m(DOUBLE_ID, 14, 29)] ; "adjacent_blocks")]
    #[test_case(b"END BEGIN", &[] ; "anchors_without_structure")]
    fn double_anchored_rule_deduplicates(buf: &[u8], expected: &[Match]) {
        assert_eq!(scan(&[DOUBLE], buf), expected);
    }

    #[test_case(b"num_2468", &[m(VERIFIED_ID, 0, 8)] ; "verify_accepts")]
    #[test_case(b"num_2461", &[] ; "verify_rejects")]
    #[test_case(b"num_2461 num_0000", &[m(VERIFIED_ID, 9, 17)] ; "verify_rejects_only_failing")]
    fn verify_hook(buf: &[u8], expected: &[Match]) {
        assert_eq!(scan(&[VERIFIED], buf), expected);
    }

    #[test_case(b"live_tok_1234", &[m(LONG_PREFIX_ID, 0, 13)] ; "embedded_anchor_is_not_a_hit")]
    #[test_case(b"live_tok_1234 tok_5678", &[m(LONG_PREFIX_ID, 0, 13), m(PREFIX_ID, 14, 22)] ; "shorter_anchor_still_hits_elsewhere")]
    fn overlapping_anchors_resolve_to_leftmost_longest(buf: &[u8], expected: &[Match]) {
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
}
