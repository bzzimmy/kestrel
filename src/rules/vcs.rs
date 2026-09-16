use crate::rules::Rule;

pub const RULES: &[Rule] = &[Rule {
    id: "github-token",
    anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
    pattern: r"\bgh[oprsu]_[A-Za-z0-9]{36}\b",
    verify: None,
}];

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::RULES;

    const GITHUB: &str = "github-token";
    const GHP: &[u8] = b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    #[test_case(b"token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\"", GITHUB, GHP ; "github_quoted")]
    #[test_case(b"https://gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@github.com", GITHUB, b"gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ; "github_oauth_in_url")]
    fn single_match(buf: &[u8], rule_id: &'static str, secret: &[u8]) {
        assert_eq!(scan(buf), [(rule_id, secret)]);
    }

    #[test_case(b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678" ; "github_too_short")]
    #[test_case(b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789A" ; "github_too_long")]
    #[test_case(b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123-56789" ; "github_bad_charset")]
    #[test_case(b"ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ; "github_unknown_prefix")]
    fn no_match(buf: &[u8]) {
        assert_eq!(scan(buf), []);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let buf = [GHP, b"\n", GHP].concat();
        assert_eq!(scan(&buf), [(GITHUB, GHP), (GITHUB, GHP)]);
    }
}
