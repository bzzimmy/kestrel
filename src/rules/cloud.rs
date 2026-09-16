use crate::rules::Rule;

pub const RULES: &[Rule] = &[
    Rule {
        id: "aws-access-key",
        anchors: &["AKIA", "ASIA"],
        pattern: r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b",
        verify: None,
    },
    Rule {
        id: "aws-secret-key",
        anchors: &[
            "aws_secret_access_key",
            "AWS_SECRET_ACCESS_KEY",
            "secretAccessKey",
        ],
        pattern: keyword_gated!(
            "(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey)",
            "A-Za-z0-9/+",
            "{40}"
        ),
        verify: None,
    },
    Rule {
        id: "private-key",
        anchors: &["-----BEGIN", "PRIVATE KEY-----"],
        pattern: r"-----BEGIN[ A-Z0-9_-]{0,32}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9_-]{0,32}PRIVATE KEY(?: BLOCK)?-----",
        verify: None,
    },
];

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::RULES;

    const AWS_ACCESS: &str = "aws-access-key";
    const AWS_SECRET: &str = "aws-secret-key";
    const PRIVATE_KEY: &str = "private-key";

    const AKIA: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
    const ASIA: &[u8] = b"ASIAIOSFODNN7EXAMPLE";
    const AWS_SECRET_VALUE: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const EC_KEY: &[u8] = b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ6H2X\nAwEHoUQDQgAE\n-----END EC PRIVATE KEY-----";
    const PGP_KEY: &[u8] = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    #[test_case(b"AKIAIOSFODNN7EXAMPLE", AWS_ACCESS, AKIA ; "aws_access_bare")]
    #[test_case(b"key: ASIAIOSFODNN7EXAMPLE\n", AWS_ACCESS, ASIA ; "aws_access_session_anchor")]
    #[test_case(b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_ini")]
    #[test_case(b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_env_at_end")]
    #[test_case(b"\"aws_secret_access_key\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_json")]
    #[test_case(b"secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',", AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_js")]
    #[test_case(b"'aws_secret_access_key' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_php_arrow")]
    #[test_case(EC_KEY, PRIVATE_KEY, EC_KEY ; "ec_private_key")]
    #[test_case(PGP_KEY, PRIVATE_KEY, PGP_KEY ; "pgp_private_key_block")]
    fn single_match(buf: &[u8], rule_id: &'static str, secret: &[u8]) {
        assert_eq!(scan(buf), [(rule_id, secret)]);
    }

    #[test_case(b"AKIAIOSFODNN7EXAMPL" ; "aws_access_too_short")]
    #[test_case(b"AKIAIOSFODNN7EXAMPLE1" ; "aws_access_too_long")]
    #[test_case(b"AKIAiosfodnn7example" ; "aws_access_lowercase")]
    #[test_case(b"AKIA1OSFODNN7EXAMPLE" ; "aws_access_digit_outside_base32")]
    #[test_case(b"AKIB IOSFODNN7EXAMPLE" ; "aws_access_wrong_prefix")]
    #[test_case(b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE" ; "aws_secret_too_short")]
    #[test_case(b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY/" ; "aws_secret_too_long")]
    #[test_case(b"aws_secret_access_key                  = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws_secret_gap_too_large")]
    #[test_case(b"aws_secret_access_key = process.env.AWS_SECRET_ACCESS_KEY" ; "aws_secret_env_reference")]
    #[test_case(b"secretAccessKey wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws_secret_no_separator")]
    #[test_case(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" ; "certificate_is_not_private_key")]
    #[test_case(b"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n" ; "private_key_without_footer")]
    fn no_match(buf: &[u8]) {
        assert_eq!(scan(buf), []);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let buf = [AKIA, b"\n", ASIA, b"\n", AKIA].concat();
        assert_eq!(
            scan(&buf),
            [(AWS_ACCESS, AKIA), (AWS_ACCESS, ASIA), (AWS_ACCESS, AKIA)]
        );
    }
}
