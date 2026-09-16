use crate::rules::Rule;

pub const RULES: &[Rule] = &[
    Rule {
        id: "vault-token",
        anchors: &["hvs.", "hvb."],
        pattern: r"\b(hv(?:s\.[A-Za-z0-9_-]{90,120}|b\.[A-Za-z0-9_-]{138,300}))(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "terraform-cloud-token",
        anchors: &[".atlasv1."],
        pattern: r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,70}\b",
        verify: None,
    },
    Rule {
        id: "doppler-token",
        anchors: &[
            "dp.st.",
            "dp.ct.",
            "dp.pt.",
            "dp.sa.",
            "dp.scim.",
            "dp.audit.",
        ],
        pattern: r"\bdp\.(?:st\.(?:[a-z0-9_-]{2,35}\.)?|(?:ct|pt|sa|scim|audit)\.)[A-Za-z0-9]{40,44}\b",
        verify: None,
    },
    Rule {
        id: "onepassword-service-account-token",
        anchors: &["ops_eyJ"],
        pattern: r"\b(ops_eyJ[A-Za-z0-9_-]{250,2000})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
];

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::RULES;

    const VAULT: &str = "vault-token";
    const TERRAFORM: &str = "terraform-cloud-token";
    const DOPPLER: &str = "doppler-token";
    const ONEPASSWORD: &str = "onepassword-service-account-token";

    const TFC_PREFIX: &str = "AbCdEfGhIjKlMn";
    const DOPPLER_BODY: &str = "bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";
    const DOPPLER_SERVICE: &str = "dp.st.prd.bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";
    const DOPPLER_PERSONAL: &str = "dp.pt.bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    fn repeat(byte: u8, count: usize) -> String {
        String::from_utf8(vec![byte; count]).unwrap_or_default()
    }

    #[test_case(&format!("VAULT_TOKEN=hvs.CAESI{}\n", repeat(b'a', 95)), VAULT, &format!("hvs.CAESI{}", repeat(b'a', 95)) ; "vault_service_env")]
    #[test_case(&format!("{{\"client_token\": \"hvs.{}-_\"}}", repeat(b'A', 88)), VAULT, &format!("hvs.{}-_", repeat(b'A', 88)) ; "vault_service_json_min")]
    #[test_case(&format!("hvs.{}", repeat(b'a', 120)), VAULT, &format!("hvs.{}", repeat(b'a', 120)) ; "vault_service_max")]
    #[test_case(&format!("token: hvb.{}", repeat(b'b', 138)), VAULT, &format!("hvb.{}", repeat(b'b', 138)) ; "vault_batch_min")]
    #[test_case(&format!("hvb.{}", repeat(b'b', 300)), VAULT, &format!("hvb.{}", repeat(b'b', 300)) ; "vault_batch_max")]
    #[test_case(&format!("credentials \"app.terraform.io\" {{\n  token = \"{TFC_PREFIX}.atlasv1.{}\"\n}}", repeat(b'z', 64)), TERRAFORM, &format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 64)) ; "terraform_cloud_hcl")]
    #[test_case(&format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 60)), TERRAFORM, &format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 60)) ; "terraform_cloud_min")]
    #[test_case(&format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 70)), TERRAFORM, &format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 70)) ; "terraform_cloud_max")]
    #[test_case(&format!("DOPPLER_TOKEN='{DOPPLER_SERVICE}'"), DOPPLER, DOPPLER_SERVICE ; "doppler_service_with_config")]
    #[test_case(&format!("dp.st.{DOPPLER_BODY}"), DOPPLER, &format!("dp.st.{DOPPLER_BODY}") ; "doppler_service_legacy_no_config")]
    #[test_case(&format!("dp.st.my-config_2.{DOPPLER_BODY}"), DOPPLER, &format!("dp.st.my-config_2.{DOPPLER_BODY}") ; "doppler_service_config_with_symbols")]
    #[test_case(&format!("dp.ct.{DOPPLER_BODY}"), DOPPLER, &format!("dp.ct.{DOPPLER_BODY}") ; "doppler_cli")]
    #[test_case(&format!("Authorization: Bearer {DOPPLER_PERSONAL}"), DOPPLER, DOPPLER_PERSONAL ; "doppler_personal")]
    #[test_case(&format!("dp.sa.{DOPPLER_BODY}"), DOPPLER, &format!("dp.sa.{DOPPLER_BODY}") ; "doppler_service_account")]
    #[test_case(&format!("dp.scim.{DOPPLER_BODY}"), DOPPLER, &format!("dp.scim.{DOPPLER_BODY}") ; "doppler_scim")]
    #[test_case(&format!("dp.audit.{DOPPLER_BODY}"), DOPPLER, &format!("dp.audit.{DOPPLER_BODY}") ; "doppler_audit")]
    #[test_case(&format!("dp.pt.{}", repeat(b'a', 40)), DOPPLER, &format!("dp.pt.{}", repeat(b'a', 40)) ; "doppler_min")]
    #[test_case(&format!("dp.pt.{}", repeat(b'a', 44)), DOPPLER, &format!("dp.pt.{}", repeat(b'a', 44)) ; "doppler_max")]
    #[test_case(&format!("export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ{}\n", repeat(b'a', 700)), ONEPASSWORD, &format!("ops_eyJ{}", repeat(b'a', 700)) ; "onepassword_env")]
    #[test_case(&format!("ops_eyJ{}-_", repeat(b'a', 248)), ONEPASSWORD, &format!("ops_eyJ{}-_", repeat(b'a', 248)) ; "onepassword_min")]
    #[test_case(&format!("ops_eyJ{}==", repeat(b'a', 300)), ONEPASSWORD, &format!("ops_eyJ{}", repeat(b'a', 300)) ; "onepassword_padding_excluded")]
    fn single_match(buf: &str, rule_id: &'static str, secret: &str) {
        assert_eq!(scan(buf.as_bytes()), [(rule_id, secret.as_bytes())]);
    }

    #[test_case(&format!("hvs.{}", repeat(b'a', 89)) ; "vault_service_too_short")]
    #[test_case(&format!("hvs.{}", repeat(b'a', 121)) ; "vault_service_too_long")]
    #[test_case(&format!("hvs.{}.{}", repeat(b'a', 50), repeat(b'a', 50)) ; "vault_service_bad_charset")]
    #[test_case(&format!("hvb.{}", repeat(b'b', 137)) ; "vault_batch_too_short")]
    #[test_case(&format!("hvb.{}", repeat(b'b', 301)) ; "vault_batch_too_long")]
    #[test_case(&format!("hvr.{}", repeat(b'a', 100)) ; "vault_unknown_prefix")]
    #[test_case("s.AbCdEfGhIjKlMnOpQrStUvWx" ; "vault_legacy_service_ignored")]
    #[test_case(&format!("AbCdEfGhIjKlM.atlasv1.{}", repeat(b'z', 64)) ; "terraform_cloud_prefix_too_short")]
    #[test_case(&format!("AbCdEfGhIjKlMnO.atlasv1.{}", repeat(b'z', 64)) ; "terraform_cloud_prefix_too_long")]
    #[test_case(&format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 59)) ; "terraform_cloud_suffix_too_short")]
    #[test_case(&format!("{TFC_PREFIX}.atlasv1.{}", repeat(b'z', 71)) ; "terraform_cloud_suffix_too_long")]
    #[test_case(&format!("{TFC_PREFIX}.atlasv2.{}", repeat(b'z', 64)) ; "terraform_cloud_wrong_version")]
    #[test_case("dp.pt.tooshort" ; "doppler_too_short")]
    #[test_case(&format!("dp.pt.{}", repeat(b'a', 45)) ; "doppler_too_long")]
    #[test_case(&format!("dp.pt.{}-{}", repeat(b'a', 20), repeat(b'a', 25)) ; "doppler_bad_charset")]
    #[test_case(&format!("dp.said.{DOPPLER_BODY}") ; "doppler_identity_ignored")]
    #[test_case(&format!("dp.xx.{DOPPLER_BODY}") ; "doppler_unknown_kind")]
    #[test_case(&format!("dp.st.p.{DOPPLER_BODY}") ; "doppler_service_config_too_short")]
    #[test_case(&format!("ops_eyJ{}", repeat(b'a', 249)) ; "onepassword_too_short")]
    #[test_case(&format!("ops_eyJ{}", repeat(b'a', 2001)) ; "onepassword_too_long")]
    #[test_case(&format!("ops_eyJ{}+/{}", repeat(b'a', 100), repeat(b'a', 200)) ; "onepassword_standard_base64_rejected")]
    #[test_case(&format!("ops_abc{}", repeat(b'a', 300)) ; "onepassword_not_json_payload")]
    fn no_match(buf: &str) {
        assert_eq!(scan(buf.as_bytes()), []);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let buf = format!("{DOPPLER_SERVICE}\n{DOPPLER_PERSONAL}\n{DOPPLER_SERVICE}");
        assert_eq!(
            scan(buf.as_bytes()),
            [
                (DOPPLER, DOPPLER_SERVICE.as_bytes()),
                (DOPPLER, DOPPLER_PERSONAL.as_bytes()),
                (DOPPLER, DOPPLER_SERVICE.as_bytes())
            ]
        );
    }
}
