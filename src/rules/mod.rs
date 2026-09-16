mod cloud;
mod vcs;

pub struct Rule {
    pub id: &'static str,
    pub anchors: &'static [&'static str],
    pub pattern: &'static str,
    pub verify: Option<fn(&[u8]) -> bool>,
}

const RULE_SETS: &[&[Rule]] = &[vcs::RULES, cloud::RULES];

pub fn all() -> impl Iterator<Item = &'static Rule> {
    RULE_SETS.iter().copied().flatten()
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
}
