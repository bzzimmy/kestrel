use crate::rules::Rule;

/// Well-known Azurite (`devstoreaccount1`) emulator key.
const AZURITE_ACCOUNT_KEY: &[u8] =
    b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const SCHEME_SEPARATOR: &[u8] = b"://";
/// Host fragments (ASCII case-insensitive) that mark a placeholder host.
const PLACEHOLDER_HOSTS: &[&[u8]] = &[b"localhost", b"127.", b"0.0.0.0", b"example", b"<"];
/// Whole passwords (ASCII case-insensitive) that are placeholders.
const PLACEHOLDER_PASSWORDS: &[&[u8]] = &[b"password", b"pass", b"changeme", b"secret"];
/// Password fragments (ASCII case-insensitive) that mark a placeholder.
const PLACEHOLDER_PASSWORD_FRAGMENTS: &[&[u8]] = &[b"xxx", b"<", b"${", b"%s"];

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
            "[A-Za-z0-9/+]{40}",
            "A-Za-z0-9/+"
        ),
        verify: None,
    },
    Rule {
        id: "aws-bedrock-api-key",
        anchors: &["ABSK", "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"],
        pattern: r"\b(ABSK[A-Za-z0-9+/]{109,269}={0,2}|bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/]{0,1000}={0,2})(?:[^A-Za-z0-9+/=]|\z)",
        verify: None,
    },
    Rule {
        id: "gcp-oauth-client-secret",
        anchors: &["GOCSPX-"],
        pattern: r"\b(GOCSPX-[A-Za-z0-9_-]{28})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    // Reports the `client_email` of a service account JSON; the embedded
    // private key is reported separately by `private-key`. The 2500-byte
    // span covers the RSA-2048 key Google emits between `type` and
    // `client_email`.
    Rule {
        id: "gcp-service-account",
        anchors: &[
            "\"type\": \"service_account\"",
            "\"type\":\"service_account\"",
        ],
        pattern: r#""type":\s{0,8}"service_account"[\s\S]{0,2500}?"client_email":\s{0,8}"([^"\s@]{1,64}@[^"\s]{4,128})""#,
        verify: None,
    },
    Rule {
        id: "azure-storage-account-key",
        anchors: &["AccountKey="],
        pattern: r"AccountKey=([A-Za-z0-9+/]{86}==)(?:[^A-Za-z0-9+/=]|\z)",
        verify: Some(is_not_azurite_key),
    },
    Rule {
        id: "alibaba-access-key-id",
        anchors: &["LTAI"],
        pattern: r"\bLTAI[A-Za-z0-9]{20}\b",
        verify: None,
    },
    Rule {
        id: "digitalocean-token",
        anchors: &["dop_v1_", "doo_v1_", "dor_v1_"],
        pattern: r"\bdo[opr]_v1_[a-f0-9]{64}\b",
        verify: None,
    },
    Rule {
        id: "cloudflare-token",
        anchors: &["cfut_", "cfat_", "cfk_", "v1.0-"],
        pattern: r"\b(cf(?:ut|at|k)_[A-Za-z0-9]{40}[a-f0-9]{8}|v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "cloudflare-legacy-token",
        anchors: &["CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"],
        pattern: keyword_gated!(
            "(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)",
            "[A-Za-z0-9_-]{40}",
            "A-Za-z0-9_-"
        ),
        verify: None,
    },
    Rule {
        id: "netlify-token",
        anchors: &["nfp_", "nfo_", "nfc_", "nfu_", "nfb_"],
        pattern: r"\b(nf[bcopu]_[A-Za-z0-9_-]{36})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "vercel-token",
        anchors: &["vcp_", "vci_", "vca_", "vcr_", "vck_"],
        pattern: r"\b(vc[acikpr]_[A-Za-z0-9_-]{56})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "flyio-token",
        anchors: &["fo1_", "fm1_", "fm2_"],
        pattern: r"\b(f(?:o1|m[12])_[A-Za-z0-9+/=_-]{100,1000})(?:[^A-Za-z0-9+/=_-]|\z)",
        verify: None,
    },
    Rule {
        id: "render-api-key",
        anchors: &["rnd_"],
        pattern: r"\brnd_[A-Za-z0-9]{24,64}\b",
        verify: None,
    },
    Rule {
        id: "supabase-token",
        anchors: &["sb_secret_", "sbp_"],
        pattern: r"\b(sb_secret_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}|sbp_(?:v0_)?[a-f0-9]{32,64})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "planetscale-token",
        anchors: &["pscale_tkn_", "pscale_pw_", "pscale_oauth_"],
        pattern: r"\b(pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_-]{32,64})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "mongodb-atlas-service-account-secret",
        anchors: &["mdb_sa_sk_"],
        pattern: r"\b(mdb_sa_sk_[A-Za-z0-9_-]{20,64})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "database-uri",
        anchors: &[
            "postgres://",
            "postgresql://",
            "mysql://",
            "mongodb://",
            "mongodb+srv://",
            "redis://",
            "rediss://",
            "amqp://",
            "amqps://",
        ],
        pattern: r#"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^:/@\s'"`]{0,64}:[^/@\s'"`]{1,128}@[^\s'"`/?@:,]{1,253}(?::[0-9]{1,5})?(?:,[^\s'"`/?@:,]{1,253}(?::[0-9]{1,5})?){0,8}(?:[/?][A-Za-z0-9._~!$&*+,;=:@%/?-]{0,256})?"#,
        verify: Some(has_real_credentials),
    },
    Rule {
        id: "private-key",
        anchors: &["-----BEGIN", "PRIVATE KEY-----"],
        pattern: r"-----BEGIN[ A-Z0-9_-]{0,32}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9_-]{0,32}PRIVATE KEY(?: BLOCK)?-----",
        verify: None,
    },
];

fn is_not_azurite_key(secret: &[u8]) -> bool {
    secret != AZURITE_ACCOUNT_KEY
}

/// True if a `scheme://user:pass@host` URI carries a non-empty password and
/// neither the password nor the host is a placeholder.
fn has_real_credentials(uri: &[u8]) -> bool {
    let Some(scheme_end) = uri
        .windows(SCHEME_SEPARATOR.len())
        .position(|window| window == SCHEME_SEPARATOR)
    else {
        return false;
    };
    let rest = &uri[scheme_end + SCHEME_SEPARATOR.len()..];
    let Some(at) = rest.iter().position(|&byte| byte == b'@') else {
        return false;
    };
    let userinfo = &rest[..at];
    let password = userinfo
        .iter()
        .position(|&byte| byte == b':')
        .map_or(&[][..], |colon| &userinfo[colon + 1..]);
    let authority = &rest[at + 1..];
    let host_end = authority
        .iter()
        .position(|&byte| matches!(byte, b':' | b'/' | b'?' | b','))
        .unwrap_or(authority.len());
    let host = &authority[..host_end];
    !password.is_empty()
        && !PLACEHOLDER_PASSWORDS
            .iter()
            .any(|word| password.eq_ignore_ascii_case(word))
        && !PLACEHOLDER_PASSWORD_FRAGMENTS
            .iter()
            .any(|fragment| contains_ignore_ascii_case(password, fragment))
        && !PLACEHOLDER_HOSTS
            .iter()
            .any(|fragment| contains_ignore_ascii_case(host, fragment))
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::{RULES, has_real_credentials};

    const AWS_ACCESS: &str = "aws-access-key";
    const AWS_SECRET: &str = "aws-secret-key";
    const BEDROCK: &str = "aws-bedrock-api-key";
    const GCP_OAUTH: &str = "gcp-oauth-client-secret";
    const GCP_SERVICE_ACCOUNT: &str = "gcp-service-account";
    const AZURE_STORAGE: &str = "azure-storage-account-key";
    const ALIBABA: &str = "alibaba-access-key-id";
    const DIGITALOCEAN: &str = "digitalocean-token";
    const CLOUDFLARE: &str = "cloudflare-token";
    const CLOUDFLARE_LEGACY: &str = "cloudflare-legacy-token";
    const NETLIFY: &str = "netlify-token";
    const VERCEL: &str = "vercel-token";
    const FLYIO: &str = "flyio-token";
    const RENDER: &str = "render-api-key";
    const SUPABASE: &str = "supabase-token";
    const PLANETSCALE: &str = "planetscale-token";
    const MONGODB_ATLAS: &str = "mongodb-atlas-service-account-secret";
    const DATABASE_URI: &str = "database-uri";
    const PRIVATE_KEY: &str = "private-key";

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const AKIA: &str = "AKIAIOSFODNN7EXAMPLE";
    const ASIA: &str = "ASIAIOSFODNN7EXAMPLE";
    const AWS_SECRET_VALUE: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const BEDROCK_SHORT_LIVED: &str =
        "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tP0FjdGlvbj1DYWxsV2l0aEJlYXJlclRva2Vu";
    const GOCSPX: &str = "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz01";
    const CLIENT_EMAIL: &str = "svc-demo@demo-project.iam.gserviceaccount.com";
    const AZURITE_KEY: &str =
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
    const LTAI: &str = "LTAI5tAbCdEfGhIjKlMnOpQr";
    const CF_LEGACY: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_Ab";
    const SB_SECRET: &str = "sb_secret_AbCdEfGhIjKlMnOpQrStUv_01234567";
    const PG_URI: &str = "postgres://app:Tr0ub4dor3@db-1.internal:5432/app?sslmode=require";
    const MONGO_SRV_URI: &str = "mongodb+srv://app:Tr0ub4dor3@cluster0.ab12c.mongodb.net/app";
    const MONGO_REPLICA_URI: &str =
        "mongodb://app:Tr0ub4dor3@db1.internal:27017,db2.internal:27017/app";
    const REDIS_URI: &str = "rediss://:Tr0ub4dor3@cache.internal:6380";
    const AMQP_URI: &str = "amqps://app:Tr0ub4dor3@mq.internal/vhost";
    const EC_KEY: &str = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ6H2X\nAwEHoUQDQgAE\n-----END EC PRIVATE KEY-----";
    const PGP_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    fn repeat(byte: u8, count: usize) -> String {
        String::from_utf8(vec![byte; count]).unwrap_or_default()
    }

    fn service_account_json(private_key: &str) -> String {
        format!(
            "{{\n  \"type\": \"service_account\",\n  \"project_id\": \"demo-project\",\n  \"private_key_id\": \"{}\",\n  \"private_key\": \"{private_key}\",\n  \"client_email\": \"{CLIENT_EMAIL}\",\n  \"client_id\": \"123456789012345678901\"\n}}",
            repeat(b'0', 40)
        )
    }

    #[test_case(AKIA, AWS_ACCESS, AKIA ; "aws_access_bare")]
    #[test_case(&format!("key: {ASIA}\n"), AWS_ACCESS, ASIA ; "aws_access_session_anchor")]
    #[test_case(&format!("aws_secret_access_key = {AWS_SECRET_VALUE}\n"), AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_ini")]
    #[test_case(&format!("AWS_SECRET_ACCESS_KEY={AWS_SECRET_VALUE}"), AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_env_at_end")]
    #[test_case(&format!("\"aws_secret_access_key\": \"{AWS_SECRET_VALUE}\""), AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_json")]
    #[test_case(&format!("secretAccessKey: '{AWS_SECRET_VALUE}',"), AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_js")]
    #[test_case(&format!("'aws_secret_access_key' => '{AWS_SECRET_VALUE}'"), AWS_SECRET, AWS_SECRET_VALUE ; "aws_secret_php_arrow")]
    #[test_case(&format!("AWS_BEARER_TOKEN_BEDROCK=ABSK{}==\n", repeat(b'a', 120)), BEDROCK, &format!("ABSK{}==", repeat(b'a', 120)) ; "bedrock_long_lived_env")]
    #[test_case(&format!("Bearer {BEDROCK_SHORT_LIVED}"), BEDROCK, BEDROCK_SHORT_LIVED ; "bedrock_short_lived")]
    #[test_case(&format!("\"client_secret\": \"{GOCSPX}\""), GCP_OAUTH, GOCSPX ; "gcp_oauth_client_secret_json")]
    #[test_case(&service_account_json("-----BEGIN PRIVATE KEY-----\\nMIIE\\n"), GCP_SERVICE_ACCOUNT, CLIENT_EMAIL ; "gcp_service_account_pretty_json")]
    #[test_case(&format!("{{\"type\":\"service_account\",\"project_id\":\"demo\",\"client_email\":\"{CLIENT_EMAIL}\"}}"), GCP_SERVICE_ACCOUNT, CLIENT_EMAIL ; "gcp_service_account_minified_json")]
    #[test_case(&format!("DefaultEndpointsProtocol=https;AccountName=prod;AccountKey={}==;EndpointSuffix=core.windows.net", repeat(b'a', 86)), AZURE_STORAGE, &format!("{}==", repeat(b'a', 86)) ; "azure_storage_connection_string")]
    #[test_case(&format!("accessKeyId: '{LTAI}'"), ALIBABA, LTAI ; "alibaba_access_key_id")]
    #[test_case(&format!("DIGITALOCEAN_TOKEN=dop_v1_{HEX64}"), DIGITALOCEAN, &format!("dop_v1_{HEX64}") ; "digitalocean_pat")]
    #[test_case(&format!("doo_v1_{HEX64}"), DIGITALOCEAN, &format!("doo_v1_{HEX64}") ; "digitalocean_oauth")]
    #[test_case(&format!("dor_v1_{HEX64}"), DIGITALOCEAN, &format!("dor_v1_{HEX64}") ; "digitalocean_refresh")]
    #[test_case(&format!("Authorization: Bearer cfut_{}01234567", repeat(b'A', 40)), CLOUDFLARE, &format!("cfut_{}01234567", repeat(b'A', 40)) ; "cloudflare_user_token")]
    #[test_case(&format!("cfk_{}abcdef01", repeat(b'A', 40)), CLOUDFLARE, &format!("cfk_{}abcdef01", repeat(b'A', 40)) ; "cloudflare_key")]
    #[test_case(&format!("v1.0-{}-{}", repeat(b'0', 24), repeat(b'f', 146)), CLOUDFLARE, &format!("v1.0-{}-{}", repeat(b'0', 24), repeat(b'f', 146)) ; "cloudflare_origin_ca")]
    #[test_case(&format!("CLOUDFLARE_API_TOKEN={CF_LEGACY}\n"), CLOUDFLARE_LEGACY, CF_LEGACY ; "cloudflare_legacy_env")]
    #[test_case(&format!("CF_API_TOKEN: \"{CF_LEGACY}\""), CLOUDFLARE_LEGACY, CF_LEGACY ; "cloudflare_legacy_yaml")]
    #[test_case(&format!("NETLIFY_AUTH_TOKEN=nfp_{}", repeat(b'a', 36)), NETLIFY, &format!("nfp_{}", repeat(b'a', 36)) ; "netlify_personal")]
    #[test_case(&format!("nfb_{}", repeat(b'a', 36)), NETLIFY, &format!("nfb_{}", repeat(b'a', 36)) ; "netlify_build")]
    #[test_case(&format!("VERCEL_TOKEN=vcp_{}", repeat(b'a', 56)), VERCEL, &format!("vcp_{}", repeat(b'a', 56)) ; "vercel_personal")]
    #[test_case(&format!("vck_{}", repeat(b'a', 56)), VERCEL, &format!("vck_{}", repeat(b'a', 56)) ; "vercel_key")]
    #[test_case(&format!("FlyV1 fm2_{}", repeat(b'a', 120)), FLYIO, &format!("fm2_{}", repeat(b'a', 120)) ; "flyio_macaroon")]
    #[test_case(&format!("fo1_{}", repeat(b'a', 100)), FLYIO, &format!("fo1_{}", repeat(b'a', 100)) ; "flyio_oauth")]
    #[test_case(&format!("RENDER_API_KEY=rnd_{}", repeat(b'a', 28)), RENDER, &format!("rnd_{}", repeat(b'a', 28)) ; "render")]
    #[test_case(&format!("SUPABASE_SERVICE_KEY={SB_SECRET}"), SUPABASE, SB_SECRET ; "supabase_secret")]
    #[test_case(&format!("sbp_{}", repeat(b'a', 40)), SUPABASE, &format!("sbp_{}", repeat(b'a', 40)) ; "supabase_management")]
    #[test_case(&format!("sbp_v0_{}", repeat(b'a', 40)), SUPABASE, &format!("sbp_v0_{}", repeat(b'a', 40)) ; "supabase_management_versioned")]
    #[test_case(&format!("pscale_tkn_{}", repeat(b'a', 40)), PLANETSCALE, &format!("pscale_tkn_{}", repeat(b'a', 40)) ; "planetscale_token")]
    #[test_case(&format!("pscale_pw_{}", repeat(b'a', 32)), PLANETSCALE, &format!("pscale_pw_{}", repeat(b'a', 32)) ; "planetscale_password")]
    #[test_case(&format!("pscale_oauth_{}", repeat(b'a', 64)), PLANETSCALE, &format!("pscale_oauth_{}", repeat(b'a', 64)) ; "planetscale_oauth")]
    #[test_case(&format!("mdb_sa_sk_{}", repeat(b'a', 40)), MONGODB_ATLAS, &format!("mdb_sa_sk_{}", repeat(b'a', 40)) ; "mongodb_atlas_secret")]
    #[test_case(&format!("DATABASE_URL={PG_URI}\n"), DATABASE_URI, PG_URI ; "database_uri_postgres_env")]
    #[test_case(&format!("\"uri\": \"{MONGO_SRV_URI}\""), DATABASE_URI, MONGO_SRV_URI ; "database_uri_mongodb_srv_json")]
    #[test_case(MONGO_REPLICA_URI, DATABASE_URI, MONGO_REPLICA_URI ; "database_uri_mongodb_replica_set")]
    #[test_case(&format!("url: {REDIS_URI}\n"), DATABASE_URI, REDIS_URI ; "database_uri_redis_no_user")]
    #[test_case(&format!("const broker = '{AMQP_URI}';"), DATABASE_URI, AMQP_URI ; "database_uri_amqp")]
    #[test_case(EC_KEY, PRIVATE_KEY, EC_KEY ; "ec_private_key")]
    #[test_case(PGP_KEY, PRIVATE_KEY, PGP_KEY ; "pgp_private_key_block")]
    fn single_match(buf: &str, rule_id: &'static str, secret: &str) {
        assert_eq!(scan(buf.as_bytes()), [(rule_id, secret.as_bytes())]);
    }

    #[test_case("AKIAIOSFODNN7EXAMPL" ; "aws_access_too_short")]
    #[test_case("AKIAIOSFODNN7EXAMPLE1" ; "aws_access_too_long")]
    #[test_case("AKIAiosfodnn7example" ; "aws_access_lowercase")]
    #[test_case("AKIA1OSFODNN7EXAMPLE" ; "aws_access_digit_outside_base32")]
    #[test_case("AKIB IOSFODNN7EXAMPLE" ; "aws_access_wrong_prefix")]
    #[test_case("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE" ; "aws_secret_too_short")]
    #[test_case("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY/" ; "aws_secret_too_long")]
    #[test_case("aws_secret_access_key                  = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws_secret_gap_too_large")]
    #[test_case("aws_secret_access_key = process.env.AWS_SECRET_ACCESS_KEY" ; "aws_secret_env_reference")]
    #[test_case("secretAccessKey wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws_secret_no_separator")]
    #[test_case(&format!("ABSK{}", repeat(b'a', 108)) ; "bedrock_too_short")]
    #[test_case(&format!("ABSK{}", repeat(b'a', 270)) ; "bedrock_too_long")]
    #[test_case(&format!("ABSK{}", repeat(b'-', 120)) ; "bedrock_bad_charset")]
    #[test_case("bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29" ; "bedrock_short_lived_truncated_prefix")]
    #[test_case("GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz0" ; "gcp_oauth_too_short")]
    #[test_case("GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz012" ; "gcp_oauth_too_long")]
    #[test_case("{\"type\": \"service_account\", \"project_id\": \"demo\"}" ; "gcp_service_account_without_client_email")]
    #[test_case(&format!("{{\"type\": \"authorized_user\", \"client_email\": \"{CLIENT_EMAIL}\"}}") ; "gcp_authorized_user")]
    #[test_case(&format!("{{\"type\": \"service_account\", \"client_email\": \"{}\"}}", repeat(b'a', 20)) ; "gcp_service_account_email_without_at")]
    #[test_case(&format!("AccountKey={AZURITE_KEY}") ; "azure_storage_azurite_key")]
    #[test_case(&format!("AccountKey={}==", repeat(b'a', 85)) ; "azure_storage_too_short")]
    #[test_case(&format!("AccountKey={}", repeat(b'a', 88)) ; "azure_storage_no_padding")]
    #[test_case(&format!("AccountKey={}===", repeat(b'a', 86)) ; "azure_storage_too_long")]
    #[test_case("LTAI5tAbCdEfGhIjKlMnOpQ" ; "alibaba_too_short")]
    #[test_case("LTAI5tAbCdEfGhIjKlMnOpQrS" ; "alibaba_too_long")]
    #[test_case("LTAI5tAbCdEfGhIjKlMnOp-r" ; "alibaba_bad_charset")]
    #[test_case(&format!("dop_v1_{}", &HEX64[..63]) ; "digitalocean_too_short")]
    #[test_case(&format!("dop_v1_{}", HEX64.to_uppercase()) ; "digitalocean_uppercase_hex")]
    #[test_case(&format!("dox_v1_{HEX64}") ; "digitalocean_unknown_prefix")]
    #[test_case(&format!("cfut_{}0123456", repeat(b'A', 40)) ; "cloudflare_too_short")]
    #[test_case(&format!("cfut_{}0123456g", repeat(b'A', 40)) ; "cloudflare_checksum_not_hex")]
    #[test_case(&format!("v1.0-{}-{}", repeat(b'0', 24), repeat(b'f', 145)) ; "cloudflare_origin_ca_too_short")]
    #[test_case("v1.0-beta" ; "cloudflare_origin_ca_version_string")]
    #[test_case("CLOUDFLARE_API_TOKEN=process.env.CLOUDFLARE_API_TOKEN" ; "cloudflare_legacy_env_reference")]
    #[test_case(&format!("CF_API_TOKEN={}", repeat(b'a', 39)) ; "cloudflare_legacy_too_short")]
    #[test_case(&format!("CF_API_TOKEN={}", repeat(b'a', 41)) ; "cloudflare_legacy_too_long")]
    #[test_case(&format!("nfp_{}", repeat(b'a', 35)) ; "netlify_too_short")]
    #[test_case(&format!("nfp_{}", repeat(b'a', 37)) ; "netlify_too_long")]
    #[test_case(&format!("nfx_{}", repeat(b'a', 36)) ; "netlify_unknown_prefix")]
    #[test_case(&format!("vcp_{}", repeat(b'a', 55)) ; "vercel_too_short")]
    #[test_case(&format!("vcx_{}", repeat(b'a', 56)) ; "vercel_unknown_prefix")]
    #[test_case(&format!("fm2_{}", repeat(b'a', 99)) ; "flyio_too_short")]
    #[test_case(&format!("fm3_{}", repeat(b'a', 120)) ; "flyio_unknown_prefix")]
    #[test_case(&format!("rnd_{}", repeat(b'a', 23)) ; "render_too_short")]
    #[test_case(&format!("rnd_{}_x", repeat(b'a', 28)) ; "render_underscore_inside_word")]
    #[test_case("sb_secret_AbCdEfGhIjKlMnOpQrStUv_0123456" ; "supabase_secret_short_checksum")]
    #[test_case("sb_publishable_AbCdEfGhIjKlMnOpQrStUv_01234567" ; "supabase_publishable_excluded")]
    #[test_case(&format!("sbp_{}", repeat(b'a', 31)) ; "supabase_management_too_short")]
    #[test_case(&format!("sbp_{}", repeat(b'A', 40)) ; "supabase_management_uppercase")]
    #[test_case(&format!("pscale_tkn_{}", repeat(b'a', 31)) ; "planetscale_too_short")]
    #[test_case(&format!("pscale_tkn_{}", repeat(b'a', 65)) ; "planetscale_too_long")]
    #[test_case(&format!("pscale_api_{}", repeat(b'a', 40)) ; "planetscale_unknown_prefix")]
    #[test_case(&format!("mdb_sa_sk_{}", repeat(b'a', 19)) ; "mongodb_atlas_too_short")]
    #[test_case(&format!("mdb_sa_id_{}", repeat(b'a', 40)) ; "mongodb_atlas_id_not_secret")]
    #[test_case("postgres://app:Tr0ub4dor3@localhost:5432/app" ; "database_uri_localhost")]
    #[test_case("mysql://root:Tr0ub4dor3@127.0.0.1/app" ; "database_uri_loopback")]
    #[test_case("redis://:Tr0ub4dor3@0.0.0.0:6379" ; "database_uri_any_address")]
    #[test_case("postgres://app:Tr0ub4dor3@db.example.com/app" ; "database_uri_example_host")]
    #[test_case("mongodb+srv://app:Tr0ub4dor3@<cluster>.mongodb.net/app" ; "database_uri_placeholder_host")]
    #[test_case("postgres://app:password@db.internal/app" ; "database_uri_password_placeholder")]
    #[test_case("postgres://app:PASS@db.internal/app" ; "database_uri_pass_placeholder_uppercase")]
    #[test_case("amqp://guest:changeme@mq.internal" ; "database_uri_changeme")]
    #[test_case("mysql://app:xxxxxxxx@db.internal/app" ; "database_uri_xxx")]
    #[test_case("mongodb://app:<password>@cluster0.mongodb.net/app" ; "database_uri_angle_password")]
    #[test_case("postgres://app:${DB_PASSWORD}@db.internal/app" ; "database_uri_shell_template")]
    #[test_case("postgres://%s:%s@%s:%d/%s" ; "database_uri_format_string")]
    #[test_case("postgres://app@db.internal/app" ; "database_uri_no_password")]
    #[test_case("postgres://app:@db.internal/app" ; "database_uri_empty_password")]
    #[test_case("postgres://db.internal:5432/app" ; "database_uri_no_userinfo")]
    #[test_case("https://app:Tr0ub4dor3@api.internal" ; "database_uri_http_scheme")]
    #[test_case("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" ; "certificate_is_not_private_key")]
    #[test_case("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n" ; "private_key_without_footer")]
    fn no_match(buf: &str) {
        assert_eq!(scan(buf.as_bytes()), []);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let dop = format!("dop_v1_{HEX64}");
        let buf = format!("{AKIA}\n{dop}\n{AKIA}");
        assert_eq!(
            scan(buf.as_bytes()),
            [
                (AWS_ACCESS, AKIA.as_bytes()),
                (DIGITALOCEAN, dop.as_bytes()),
                (AWS_ACCESS, AKIA.as_bytes())
            ]
        );
    }

    #[test]
    fn service_account_json_reports_client_email_and_private_key() {
        let pem = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBg\\n-----END PRIVATE KEY-----";
        let buf = service_account_json(pem);
        assert_eq!(
            scan(buf.as_bytes()),
            [
                (GCP_SERVICE_ACCOUNT, CLIENT_EMAIL.as_bytes()),
                (PRIVATE_KEY, pem.as_bytes())
            ]
        );
    }

    #[test_case(b"postgres://app:Tr0ub4dor3@db.internal" ; "postgres")]
    #[test_case(b"redis://:Tr0ub4dor3@cache.internal:6379" ; "empty_user")]
    #[test_case(b"mongodb+srv://app:Tr0ub4dor3@cluster0.ab12c.mongodb.net/app?retryWrites=true" ; "path_and_query")]
    #[test_case(b"postgres://app:Compass2024@db.internal" ; "password_containing_pass_word")]
    #[test_case(b"mysql://app:Tr0ub4dor3@10.0.0.5:3306/app" ; "private_ip")]
    fn credentials_accepted(uri: &[u8]) {
        assert!(has_real_credentials(uri));
    }

    #[test_case(b"postgres://app@db.internal" ; "no_password")]
    #[test_case(b"postgres://app:@db.internal" ; "empty_password")]
    #[test_case(b"postgres://app:Password@db.internal" ; "password_word")]
    #[test_case(b"postgres://app:pass@db.internal" ; "pass_word")]
    #[test_case(b"postgres://app:changeme@db.internal" ; "changeme_word")]
    #[test_case(b"postgres://app:SECRET@db.internal" ; "secret_word")]
    #[test_case(b"postgres://app:XXXXXX@db.internal" ; "xxx_fragment")]
    #[test_case(b"postgres://app:<pw>@db.internal" ; "angle_password")]
    #[test_case(b"postgres://app:${PW}@db.internal" ; "shell_template_password")]
    #[test_case(b"postgres://app:%s@db.internal" ; "format_string_password")]
    #[test_case(b"postgres://app:Tr0ub4dor3@localhost" ; "localhost")]
    #[test_case(b"postgres://app:Tr0ub4dor3@LOCALHOST:5432" ; "localhost_uppercase")]
    #[test_case(b"postgres://app:Tr0ub4dor3@127.0.0.1" ; "loopback")]
    #[test_case(b"postgres://app:Tr0ub4dor3@0.0.0.0" ; "any_address")]
    #[test_case(b"postgres://app:Tr0ub4dor3@example.com" ; "example_host")]
    #[test_case(b"postgres://app:Tr0ub4dor3@<host>" ; "angle_host")]
    #[test_case(b"postgres://db.internal" ; "no_userinfo")]
    #[test_case(b"not a uri" ; "no_scheme")]
    fn credentials_rejected(uri: &[u8]) {
        assert!(!has_real_credentials(uri));
    }
}
