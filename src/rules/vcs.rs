use crate::rules::Rule;

pub const RULES: &[Rule] = &[
    Rule {
        id: "github-token",
        anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        pattern: r"\b(?:gh[oprsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})",
        verify: None,
    },
    Rule {
        id: "gitlab-token",
        anchors: &[
            "glpat-", "glrt-", "gldt-", "glffct-", "glsoat-", "glcbt-", "glagent-", "gloas-",
            "glptt-",
        ],
        pattern: r"\b(gl(?:pat-(?:[A-Za-z0-9_-]{27,300}\.[0-9a-z]{2}(?:\.[0-9a-z]{9}|[0-9a-z]{7})|[A-Za-z0-9_-]{20})|rt-(?:t[0-9]_[A-Za-z0-9_-]{27,300}\.[0-9a-z]{9}|[A-Za-z0-9_-]{20})|(?:dt|ffct|soat)-[A-Za-z0-9_-]{20}|cbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_-]{20}|agent-[A-Za-z0-9_-]{50}|oas-[A-Za-z0-9_-]{64}|ptt-[0-9a-f]{40}))(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "atlassian-token",
        anchors: &["ATATT3xFfGF0", "ATCTT3xFfGN0", "ATBB"],
        pattern: r"\b(AT(?:ATT3xFfGF0|CTT3xFfGN0)[A-Za-z0-9_=-]{100,400}|ATBB[A-Za-z0-9]{32})(?:[^A-Za-z0-9_=-]|\z)",
        verify: None,
    },
    Rule {
        id: "circleci-token",
        anchors: &["CCIPAT_", "CCIPRJ_"],
        pattern: r"\bCCIP(?:AT|RJ)_[A-Za-z0-9]{22}_[a-f0-9]{40}",
        verify: None,
    },
    Rule {
        id: "npm-token",
        anchors: &["npm_"],
        pattern: r"\bnpm_[A-Za-z0-9]{36}",
        verify: None,
    },
    Rule {
        id: "pypi-token",
        anchors: &["pypi-AgEIcHlwaS5vcmc"],
        pattern: r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "rubygems-token",
        anchors: &["rubygems_"],
        pattern: r"\brubygems_[a-f0-9]{48}",
        verify: None,
    },
    Rule {
        id: "crates-io-token",
        anchors: &["cio"],
        pattern: r"\bcio[A-Za-z0-9]{32}\b",
        verify: None,
    },
    Rule {
        id: "nuget-api-key",
        anchors: &["oy2"],
        pattern: r"\boy2[a-z0-9]{43}\b",
        verify: None,
    },
    Rule {
        id: "dockerhub-token",
        anchors: &["dckr_pat_", "dckr_oat_"],
        pattern: r"\b(dckr_(?:pat_[A-Za-z0-9_-]{27}|oat_[A-Za-z0-9_-]{32}))(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "artifactory-token",
        anchors: &["AKCp", "cmVmd"],
        pattern: r"\b(?:AKCp[A-Za-z0-9]{68,70}|cmVmd[A-Za-z0-9]{59})\b",
        verify: None,
    },
];

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::RULES;

    const GITHUB: &str = "github-token";
    const GITLAB: &str = "gitlab-token";
    const ATLASSIAN: &str = "atlassian-token";
    const CIRCLECI: &str = "circleci-token";
    const NPM: &str = "npm-token";
    const PYPI: &str = "pypi-token";
    const RUBYGEMS: &str = "rubygems-token";
    const CRATES: &str = "crates-io-token";
    const NUGET: &str = "nuget-api-key";
    const DOCKERHUB: &str = "dockerhub-token";
    const ARTIFACTORY: &str = "artifactory-token";

    const HEX40: &str = "0123456789abcdef0123456789abcdef01234567";
    const GHP: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const GLPAT: &str = "glpat-AbCdEfGhIjKlMnOpQrSt";
    const GLPAT_ROUTABLE: &str = "glpat-1y_tT5u1NrszeXn9Z0zC-Am8M2UUDl7xcDlk.01abcdefg";
    const GLPAT_VERSIONED: &str = "glpat-1y_tT5u1NrszeXn9Z0zC-Am8M2UUDl7xcDlk.01.0abcdefgh";
    const GLRT_ROUTABLE: &str = "glrt-t1_1y_tT5u1NrszeXn9Z0zC-Am8M2UUDl7xcDlk.01abcdefg";
    const ATBB: &str = "ATBBdWnPxkrgehVZUxc4gRN7WqQt7A3E1A2A";
    const NPM_TOKEN: &str = "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const CRATES_TOKEN: &str = "cioAbCdEfGhIjKlMnOpQrStUvWxYz012345";
    const NUGET_KEY: &str = "oy2abcdefghijklmnopqrstuvwxyz0123456789abcdefg";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    fn repeat(byte: u8, count: usize) -> String {
        String::from_utf8(vec![byte; count]).unwrap_or_default()
    }

    #[test_case(&format!("token = \"{GHP}\""), GITHUB, GHP ; "github_quoted")]
    #[test_case("https://gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@github.com", GITHUB, "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ; "github_oauth_in_url")]
    #[test_case("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789GITHUB_BRANCH", GITHUB, GHP ; "github_glued_to_following_word")]
    #[test_case(&format!("github_pat_{}_{}", repeat(b'A', 22), repeat(b'b', 59)), GITHUB, &format!("github_pat_{}_{}", repeat(b'A', 22), repeat(b'b', 59)) ; "github_fine_grained_pat")]
    #[test_case(&format!("PRIVATE-TOKEN: {GLPAT}\n"), GITLAB, GLPAT ; "gitlab_pat_legacy")]
    #[test_case(GLPAT_ROUTABLE, GITLAB, GLPAT_ROUTABLE ; "gitlab_pat_routable")]
    #[test_case(GLPAT_VERSIONED, GITLAB, GLPAT_VERSIONED ; "gitlab_pat_routable_versioned")]
    #[test_case("glrt-AbCdEfGhIjKlMnOpQrSt", GITLAB, "glrt-AbCdEfGhIjKlMnOpQrSt" ; "gitlab_runner_legacy")]
    #[test_case(GLRT_ROUTABLE, GITLAB, GLRT_ROUTABLE ; "gitlab_runner_routable")]
    #[test_case("gldt-AbCdEfGhIjKlMnOpQrSt", GITLAB, "gldt-AbCdEfGhIjKlMnOpQrSt" ; "gitlab_deploy")]
    #[test_case("glffct-AbCdEfGhIjKlMnOpQrSt", GITLAB, "glffct-AbCdEfGhIjKlMnOpQrSt" ; "gitlab_feature_flag")]
    #[test_case("glsoat-AbCdEfGhIjKlMnOpQrSt", GITLAB, "glsoat-AbCdEfGhIjKlMnOpQrSt" ; "gitlab_scim")]
    #[test_case("glcbt-1a_AbCdEfGhIjKlMnOpQrSt", GITLAB, "glcbt-1a_AbCdEfGhIjKlMnOpQrSt" ; "gitlab_job")]
    #[test_case(&format!("glagent-{}", repeat(b'a', 50)), GITLAB, &format!("glagent-{}", repeat(b'a', 50)) ; "gitlab_agent")]
    #[test_case(&format!("gloas-{}", repeat(b'a', 64)), GITLAB, &format!("gloas-{}", repeat(b'a', 64)) ; "gitlab_oauth_secret")]
    #[test_case(&format!("glptt-{HEX40}"), GITLAB, &format!("glptt-{HEX40}") ; "gitlab_pipeline_trigger")]
    #[test_case(&format!("Authorization: Basic ATATT3xFfGF0{}=A1B2C3D4", repeat(b'a', 171)), ATLASSIAN, &format!("ATATT3xFfGF0{}=A1B2C3D4", repeat(b'a', 171)) ; "atlassian_api_token")]
    #[test_case(&format!("ATCTT3xFfGN0{}", repeat(b'b', 150)), ATLASSIAN, &format!("ATCTT3xFfGN0{}", repeat(b'b', 150)) ; "bitbucket_access_token")]
    #[test_case(&format!("https://user:{ATBB}@bitbucket.org"), ATLASSIAN, ATBB ; "bitbucket_app_password")]
    #[test_case(&format!("CCIPAT_AbCdEfGhIjKlMnOpQrStUv_{HEX40}"), CIRCLECI, &format!("CCIPAT_AbCdEfGhIjKlMnOpQrStUv_{HEX40}") ; "circleci_personal")]
    #[test_case(&format!("CCIPRJ_AbCdEfGhIjKlMnOpQrStUv_{HEX40}"), CIRCLECI, &format!("CCIPRJ_AbCdEfGhIjKlMnOpQrStUv_{HEX40}") ; "circleci_project")]
    #[test_case(&format!("//registry.npmjs.org/:_authToken={NPM_TOKEN}\n"), NPM, NPM_TOKEN ; "npm_npmrc")]
    #[test_case(&format!("pypi-AgEIcHlwaS5vcmc{}", repeat(b'a', 150)), PYPI, &format!("pypi-AgEIcHlwaS5vcmc{}", repeat(b'a', 150)) ; "pypi")]
    #[test_case(&format!("rubygems_{HEX40}01234567"), RUBYGEMS, &format!("rubygems_{HEX40}01234567") ; "rubygems")]
    #[test_case(&format!("token = \"{CRATES_TOKEN}\""), CRATES, CRATES_TOKEN ; "crates_credentials_toml")]
    #[test_case(NUGET_KEY, NUGET, NUGET_KEY ; "nuget")]
    #[test_case("dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxY-_", DOCKERHUB, "dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxY-_" ; "dockerhub_personal")]
    #[test_case(&format!("dckr_oat_{}", repeat(b'a', 32)), DOCKERHUB, &format!("dckr_oat_{}", repeat(b'a', 32)) ; "dockerhub_organization")]
    #[test_case(&format!("AKCp{}", repeat(b'a', 69)), ARTIFACTORY, &format!("AKCp{}", repeat(b'a', 69)) ; "artifactory_api_key")]
    #[test_case(&format!("cmVmd{}", repeat(b'a', 59)), ARTIFACTORY, &format!("cmVmd{}", repeat(b'a', 59)) ; "artifactory_reference_token")]
    fn single_match(buf: &str, rule_id: &'static str, secret: &str) {
        assert_eq!(scan(buf.as_bytes()), [(rule_id, secret.as_bytes())]);
    }

    #[test_case("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678" ; "github_too_short")]
    #[test_case("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123-56789" ; "github_bad_charset")]
    #[test_case("ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ; "github_unknown_prefix")]
    #[test_case(&format!("github_pat_{}", repeat(b'A', 81)) ; "github_fine_grained_too_short")]
    #[test_case("glpat-AbCdEfGhIjKlMnOpQrS" ; "gitlab_pat_too_short")]
    #[test_case("glpat-AbCdEfGhIjKlMnOpQrStU" ; "gitlab_pat_too_long")]
    #[test_case("glpat-1y_tT5u1NrszeXn9Z0zC-Am8M2UUDl7xcDlk.01abcdef" ; "gitlab_pat_routable_short_suffix")]
    #[test_case("glrt-t1_1y_tT5u1NrszeXn9Z0zC-Am8M2UUDl7xcDlk" ; "gitlab_runner_routable_missing_suffix")]
    #[test_case("glxx-AbCdEfGhIjKlMnOpQrSt" ; "gitlab_unknown_prefix")]
    #[test_case("glptt-ABCDEF0123456789ABCDEF0123456789ABCDEF01" ; "gitlab_pipeline_trigger_uppercase_hex")]
    #[test_case(&format!("ATATT3xFfGF0{}", repeat(b'a', 50)) ; "atlassian_too_short")]
    #[test_case("ATBBdWnPxkrgehVZUxc4gRN7WqQt7A3E1A2" ; "bitbucket_app_password_too_short")]
    #[test_case(&format!("CCIPAT_AbCdEfGhIjKlMnOpQrStUv_{}", HEX40.to_uppercase()) ; "circleci_uppercase_hex")]
    #[test_case("npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678" ; "npm_too_short")]
    #[test_case("npm_AbCdEfGhIjKlMnOpQrStUvWxYz01234567-9" ; "npm_bad_charset")]
    #[test_case(&format!("pypi-AgENdGVzdC5weXBpLm9yZw{}", repeat(b'a', 150)) ; "pypi_test_index")]
    #[test_case(&format!("pypi-AgEIcHlwaS5vcmc{}", repeat(b'a', 49)) ; "pypi_too_short")]
    #[test_case(&format!("rubygems_{}", HEX40.to_uppercase()) ; "rubygems_uppercase_hex")]
    #[test_case("cioAbCdEfGhIjKlMnOpQrStUvWxYz0123456" ; "crates_too_long")]
    #[test_case("precioAbCdEfGhIjKlMnOpQrStUvWxYz012345" ; "crates_inside_word")]
    #[test_case("oy2ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFG" ; "nuget_uppercase")]
    #[test_case("dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxY-_x" ; "dockerhub_personal_too_long")]
    #[test_case(&format!("AKCp{}", repeat(b'a', 67)) ; "artifactory_too_short")]
    fn no_match(buf: &str) {
        assert_eq!(scan(buf.as_bytes()), []);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let buf = format!("{GHP}\n{GLPAT}\n{GHP}");
        assert_eq!(
            scan(buf.as_bytes()),
            [
                (GITHUB, GHP.as_bytes()),
                (GITLAB, GLPAT.as_bytes()),
                (GITHUB, GHP.as_bytes())
            ]
        );
    }
}
