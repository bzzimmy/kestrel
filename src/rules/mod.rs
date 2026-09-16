/// Pattern for a keyword-gated rule: `keywords`, a bounded gap, `=`/`:`
/// (or `=>`), optional quote, then `value` as capture group 1 followed by
/// a character outside `charset` (a character class body) or end of input.
macro_rules! keyword_gated {
    ($keywords:literal, $value:literal, $charset:literal) => {
        concat!(
            $keywords,
            r#"[^\n=:]{0,16}[=:]>?\s{0,8}["'`]?("#,
            $value,
            ")(?:[^",
            $charset,
            r"]|\z)"
        )
    };
}

mod ai;
mod cloud;
mod infra;
mod saas;
mod vcs;

pub struct Rule {
    pub id: &'static str,
    pub anchors: &'static [&'static str],
    pub pattern: &'static str,
    pub verify: Option<fn(&[u8]) -> bool>,
}

const RULE_SETS: &[&[Rule]] = &[
    vcs::RULES,
    cloud::RULES,
    infra::RULES,
    saas::RULES,
    ai::RULES,
];

pub fn all() -> impl Iterator<Item = &'static Rule> {
    RULE_SETS.iter().copied().flatten()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a rule that fails to compile is a rule bug"
)]
fn scan<'b>(rules: &[Rule], buf: &'b [u8]) -> Vec<(&'static str, &'b [u8])> {
    let matcher = crate::matcher::Matcher::new(rules).expect("rules must compile");
    matcher
        .scan(buf)
        .map(|m| (m.rule_id, &buf[m.start..m.end]))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::all;
    use crate::matcher::Matcher;

    #[test]
    fn all_rules_compile() {
        assert!(Matcher::new(all()).is_ok());
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut seen = HashSet::new();
        for rule in all() {
            assert!(seen.insert(rule.id), "duplicate rule id `{}`", rule.id);
        }
    }

    #[test]
    fn anchors_are_unique_across_rules() {
        let mut seen = HashSet::new();
        for rule in all() {
            for anchor in rule.anchors {
                assert!(seen.insert(anchor), "anchor `{anchor}` used by two rules");
            }
        }
    }
}
