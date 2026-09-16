use memchr::memchr_iter;

use crate::rules::Rule;

const SNOWFLAKE_MIN_DIGITS: usize = 17;
const SNOWFLAKE_MAX_DIGITS: usize = 19;
/// Base64 of binary data (fonts, wasm, DER) carries runs of identical
/// characters that random tokens practically never do, and encodes its many
/// zero bytes as `A`.
const MAX_REPEAT_RUN: usize = 3;
const MAX_A_PERCENT: usize = 20;

/// Every 3-char prefix of base64(three ASCII digits): the start of any
/// base64-encoded Discord snowflake.
const DISCORD_ANCHORS: &[&str] = &[
    "MDA", "MDE", "MDI", "MDM", "MDQ", "MDU", "MDY", "MDc", "MDg", "MDk", "MTA", "MTE", "MTI",
    "MTM", "MTQ", "MTU", "MTY", "MTc", "MTg", "MTk", "MjA", "MjE", "MjI", "MjM", "MjQ", "MjU",
    "MjY", "Mjc", "Mjg", "Mjk", "MzA", "MzE", "MzI", "MzM", "MzQ", "MzU", "MzY", "Mzc", "Mzg",
    "Mzk", "NDA", "NDE", "NDI", "NDM", "NDQ", "NDU", "NDY", "NDc", "NDg", "NDk", "NTA", "NTE",
    "NTI", "NTM", "NTQ", "NTU", "NTY", "NTc", "NTg", "NTk", "NjA", "NjE", "NjI", "NjM", "NjQ",
    "NjU", "NjY", "Njc", "Njg", "Njk", "NzA", "NzE", "NzI", "NzM", "NzQ", "NzU", "NzY", "Nzc",
    "Nzg", "Nzk", "ODA", "ODE", "ODI", "ODM", "ODQ", "ODU", "ODY", "ODc", "ODg", "ODk", "OTA",
    "OTE", "OTI", "OTM", "OTQ", "OTU", "OTY", "OTc", "OTg", "OTk",
];

pub const RULES: &[Rule] = &[
    Rule {
        id: "slack-bot-token",
        anchors: &["xoxb-"],
        pattern: r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,34}\b",
        verify: None,
    },
    Rule {
        id: "slack-user-token",
        anchors: &["xoxp-"],
        pattern: r"\bxoxp-(?:[0-9]{10,13}-){3}[A-Za-z0-9]{28,34}\b",
        verify: None,
    },
    Rule {
        id: "slack-app-token",
        anchors: &["xapp-"],
        pattern: r"\bxapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{64}",
        verify: None,
    },
    Rule {
        id: "slack-config-token",
        anchors: &["xoxe.xoxb-", "xoxe.xoxp-", "xoxe-"],
        pattern: r"\bxoxe(?:\.xox[bp]-[0-9]-[A-Za-z0-9]{163,166}|-[0-9]-[A-Za-z0-9]{146})\b",
        verify: None,
    },
    Rule {
        id: "slack-session-token",
        anchors: &["xoxc-"],
        pattern: r"\bxoxc-(?:[0-9]{9,15}-){3}[a-f0-9]{64}\b",
        verify: None,
    },
    Rule {
        id: "slack-cookie",
        anchors: &["xoxd-"],
        pattern: r"\b(xoxd-[A-Za-z0-9/+%_-]{100,600}={0,2})(?:[^A-Za-z0-9/+%=_-]|\z)",
        verify: None,
    },
    Rule {
        id: "discord-bot-token",
        anchors: DISCORD_ANCHORS,
        pattern: r"\b([MNO][DTjz][AEIMQUYcgk][wxyz0-5](?:[A-Za-z0-9_-]{19,20}|[A-Za-z0-9_-]{22})\.[A-Za-z0-9_-]{6}\.(?:[A-Za-z0-9_-]{27}|[A-Za-z0-9_-]{38}))(?:[^A-Za-z0-9_-]|\z)",
        verify: Some(starts_with_snowflake),
    },
    Rule {
        id: "discord-legacy-token",
        anchors: &["mfa."],
        pattern: r"\b(mfa\.[A-Za-z0-9_-]{84})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "stripe-secret-key",
        anchors: &["sk_live_", "rk_live_"],
        pattern: r"\b[sr]k_live_[A-Za-z0-9]{24,99}\b",
        verify: None,
    },
    Rule {
        id: "shopify-token",
        anchors: &["shpat_", "shppa_", "shpca_", "shpss_"],
        pattern: r"\bshp(?:at|pa|ca|ss)_[a-fA-F0-9]{32}",
        verify: None,
    },
    Rule {
        id: "square-token",
        anchors: &["sq0atp-", "sq0csp-", "EAAA"],
        pattern: r"\b(sq0(?:atp-[A-Za-z0-9_-]{22,60}|csp-[A-Za-z0-9_-]{43})|EAAA[A-Za-z0-9_+=-]{60})(?:[^A-Za-z0-9_+=-]|\z)",
        verify: Some(is_not_binary_base64),
    },
    Rule {
        id: "braintree-access-token",
        anchors: &["access_token$production$"],
        pattern: r"\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}",
        verify: None,
    },
    Rule {
        id: "plaid-access-token",
        anchors: &["access-production-"],
        pattern: r"\baccess-production-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        verify: None,
    },
    Rule {
        id: "sendgrid-api-key",
        anchors: &["SG."],
        pattern: r"\b(SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,50})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "resend-api-key",
        anchors: &["re_"],
        pattern: r"\bre_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}\b",
        verify: None,
    },
    Rule {
        id: "hubspot-token",
        anchors: &["pat-na1-", "pat-na2-", "pat-eu1-"],
        pattern: r"\bpat-(?:na[12]|eu1)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        verify: None,
    },
    Rule {
        id: "meta-access-token",
        anchors: &["EAAM", "EAAC"],
        pattern: r"\bEAA[MC][A-Za-z0-9]{100,400}\b",
        verify: Some(is_not_binary_base64),
    },
    Rule {
        id: "cloudinary-url",
        anchors: &["cloudinary://"],
        pattern: r"\bcloudinary://[0-9]{15}:[A-Za-z0-9_-]{20,32}@[a-z0-9_-]{2,64}\b",
        verify: None,
    },
    Rule {
        id: "sentry-token",
        anchors: &["sntrys_eyJ", "sntryu_", "sntrya_", "sntryi_"],
        pattern: r"\b(sntrys_eyJ[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43}|sntry[uai]_[a-f0-9]{64})(?:[^A-Za-z0-9+/]|\z)",
        verify: None,
    },
    Rule {
        id: "auth0-client-secret",
        anchors: &["AUTH0_CLIENT_SECRET", "auth0", "Auth0"],
        pattern: keyword_gated!(
            r"(?:AUTH0_CLIENT_SECRET|[aA]uth0[^\n]{0,32}?(?:client_secret|clientSecret))",
            "[A-Za-z0-9_-]{64,128}",
            "A-Za-z0-9_-"
        ),
        verify: None,
    },
];

fn is_not_binary_base64(secret: &[u8]) -> bool {
    let has_long_run = secret
        .windows(MAX_REPEAT_RUN + 1)
        .any(|window| window.iter().all(|&byte| byte == window[0]));
    let a_count = memchr_iter(b'A', secret).count();
    !has_long_run && a_count * 100 <= secret.len() * MAX_A_PERCENT
}

/// True if the token's first `.`-separated segment is base64 of a 17-19
/// digit snowflake.
fn starts_with_snowflake(secret: &[u8]) -> bool {
    let Some(segment) = secret.split(|&byte| byte == b'.').next() else {
        return false;
    };
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut digits = 0;
    for &byte in segment {
        let Some(sextet) = base64url_sextet(byte) else {
            return false;
        };
        acc = (acc << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if !u8::try_from(acc >> bits).is_ok_and(|decoded| decoded.is_ascii_digit()) {
                return false;
            }
            acc &= (1 << bits) - 1;
            digits += 1;
        }
    }
    (SNOWFLAKE_MIN_DIGITS..=SNOWFLAKE_MAX_DIGITS).contains(&digits)
}

fn base64url_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::{DISCORD_ANCHORS, RULES, starts_with_snowflake};

    const SLACK_BOT: &str = "slack-bot-token";
    const SLACK_USER: &str = "slack-user-token";
    const SLACK_APP: &str = "slack-app-token";
    const SLACK_CONFIG: &str = "slack-config-token";
    const SLACK_SESSION: &str = "slack-session-token";
    const SLACK_COOKIE: &str = "slack-cookie";
    const DISCORD_BOT: &str = "discord-bot-token";
    const DISCORD_LEGACY: &str = "discord-legacy-token";
    const STRIPE: &str = "stripe-secret-key";
    const SHOPIFY: &str = "shopify-token";
    const SQUARE: &str = "square-token";
    const BRAINTREE: &str = "braintree-access-token";
    const PLAID: &str = "plaid-access-token";
    const SENDGRID: &str = "sendgrid-api-key";
    const RESEND: &str = "resend-api-key";
    const HUBSPOT: &str = "hubspot-token";
    const META: &str = "meta-access-token";
    const CLOUDINARY: &str = "cloudinary-url";
    const SENTRY: &str = "sentry-token";
    const AUTH0: &str = "auth0-client-secret";

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const XOXB: &str = "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx";
    const XOXP: &str =
        "xoxp-1234567890-1234567890123-1234567890123-abcdef0123456789abcdef0123456789";
    const DISCORD: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GaBcDe.AbCdEfGhIjKlMnOpQrStUvWxYz0";
    const DISCORD_LEAKED: &str = "NjA3MjczNzg0NTM3NTE0MDI3.XUXOIA.bJKBgg6gs30yC5mV7e4kWnu4WaA";
    const DISCORD_MODERN: &str =
        "MTAwMzQyMDAzNDY3Mzg3MzM3Nw.GaBcDe.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_";
    const SK_LIVE: &str = "sk_live_AbCdEfGhIjKlMnOpQrStUvWx";
    const AUTH0_SECRET: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGhIjKlMnOpQrStUvWxYz01";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    fn repeat(byte: u8, count: usize) -> String {
        String::from_utf8(vec![byte; count]).unwrap_or_default()
    }

    /// Non-repeating alphanumeric filler of the given length.
    fn filler(count: usize) -> String {
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            .chars()
            .cycle()
            .take(count)
            .collect()
    }

    #[test_case(&format!("token: '{XOXB}'"), SLACK_BOT, XOXB ; "slack_bot")]
    #[test_case(XOXP, SLACK_USER, XOXP ; "slack_user")]
    #[test_case(&format!("xapp-1-A0123456789-1234567890123-{HEX64}"), SLACK_APP, &format!("xapp-1-A0123456789-1234567890123-{HEX64}") ; "slack_app")]
    #[test_case(&format!("xoxe.xoxb-1-{}", repeat(b'A', 163)), SLACK_CONFIG, &format!("xoxe.xoxb-1-{}", repeat(b'A', 163)) ; "slack_config_access")]
    #[test_case(&format!("xoxe-1-{}", repeat(b'A', 146)), SLACK_CONFIG, &format!("xoxe-1-{}", repeat(b'A', 146)) ; "slack_config_refresh")]
    #[test_case(&format!("xoxc-123456789-123456789-123456789-{HEX64}"), SLACK_SESSION, &format!("xoxc-123456789-123456789-123456789-{HEX64}") ; "slack_session")]
    #[test_case(&format!("d=xoxd-{}%3D;", repeat(b'a', 120)), SLACK_COOKIE, &format!("xoxd-{}%3D", repeat(b'a', 120)) ; "slack_cookie")]
    #[test_case(&format!("Bot {DISCORD}"), DISCORD_BOT, DISCORD ; "discord_bot")]
    #[test_case(&format!("token: '{DISCORD_LEAKED}'"), DISCORD_BOT, DISCORD_LEAKED ; "discord_bot_leaked_sample")]
    #[test_case(DISCORD_MODERN, DISCORD_BOT, DISCORD_MODERN ; "discord_bot_modern_38_hmac")]
    #[test_case(&format!("mfa.{}", repeat(b'x', 84)), DISCORD_LEGACY, &format!("mfa.{}", repeat(b'x', 84)) ; "discord_legacy")]
    #[test_case(&format!("Stripe('{SK_LIVE}')"), STRIPE, SK_LIVE ; "stripe_secret")]
    #[test_case("rk_live_AbCdEfGhIjKlMnOpQrStUvWx", STRIPE, "rk_live_AbCdEfGhIjKlMnOpQrStUvWx" ; "stripe_restricted")]
    #[test_case("shpat_0123456789abcdef0123456789abcdef", SHOPIFY, "shpat_0123456789abcdef0123456789abcdef" ; "shopify_admin")]
    #[test_case("shpss_0123456789abcdef0123456789abcdef", SHOPIFY, "shpss_0123456789abcdef0123456789abcdef" ; "shopify_shared_secret")]
    #[test_case("sq0atp-AbCdEfGhIjKlMnOpQrStUv", SQUARE, "sq0atp-AbCdEfGhIjKlMnOpQrStUv" ; "square_access")]
    #[test_case(&format!("sq0csp-{}", filler(43)), SQUARE, &format!("sq0csp-{}", filler(43)) ; "square_secret")]
    #[test_case(&format!("token: EAAA{}", filler(60)), SQUARE, &format!("EAAA{}", filler(60)) ; "square_personal_access")]
    #[test_case("access_token$production$abcdefgh12345678$0123456789abcdef0123456789abcdef", BRAINTREE, "access_token$production$abcdefgh12345678$0123456789abcdef0123456789abcdef" ; "braintree")]
    #[test_case("access-production-01234567-89ab-cdef-0123-456789abcdef", PLAID, "access-production-01234567-89ab-cdef-0123-456789abcdef" ; "plaid")]
    #[test_case(&format!("SG.{}.{}", repeat(b'a', 22), repeat(b'b', 43)), SENDGRID, &format!("SG.{}.{}", repeat(b'a', 22), repeat(b'b', 43)) ; "sendgrid")]
    #[test_case("re_AbCdEfGh_AbCdEfGhJkLmNpQrStUvWxYz", RESEND, "re_AbCdEfGh_AbCdEfGhJkLmNpQrStUvWxYz" ; "resend")]
    #[test_case("pat-na1-01234567-89ab-cdef-0123-456789abcdef", HUBSPOT, "pat-na1-01234567-89ab-cdef-0123-456789abcdef" ; "hubspot")]
    #[test_case("pat-na2-01234567-89ab-cdef-0123-456789abcdef", HUBSPOT, "pat-na2-01234567-89ab-cdef-0123-456789abcdef" ; "hubspot_na2")]
    #[test_case(&format!("EAAM{}", filler(150)), META, &format!("EAAM{}", filler(150)) ; "meta_page")]
    #[test_case("cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz1@mycloud", CLOUDINARY, "cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz1@mycloud" ; "cloudinary")]
    #[test_case(&format!("sntrys_eyJpYXQiOjE3MDAwMDAwMDAuMCwidXJsIjoiaHR0cHM6Ly9zZW50cnkuaW8ifQ==_{}", repeat(b'a', 43)), SENTRY, &format!("sntrys_eyJpYXQiOjE3MDAwMDAwMDAuMCwidXJsIjoiaHR0cHM6Ly9zZW50cnkuaW8ifQ==_{}", repeat(b'a', 43)) ; "sentry_org")]
    #[test_case(&format!("sntryu_{HEX64}"), SENTRY, &format!("sntryu_{HEX64}") ; "sentry_user")]
    #[test_case(&format!("AUTH0_CLIENT_SECRET={AUTH0_SECRET}"), AUTH0, AUTH0_SECRET ; "auth0_env")]
    #[test_case(&format!("auth0: {{ clientSecret: '{AUTH0_SECRET}' }}"), AUTH0, AUTH0_SECRET ; "auth0_nested_js")]
    #[test_case(&format!("new Auth0({{ client_secret: \"{AUTH0_SECRET}\" }})"), AUTH0, AUTH0_SECRET ; "auth0_constructor")]
    fn single_match(buf: &str, rule_id: &'static str, secret: &str) {
        assert_eq!(scan(buf.as_bytes()), [(rule_id, secret.as_bytes())]);
    }

    #[test_case("xoxb-123-456-abc" ; "slack_bot_short_ids")]
    #[test_case("https://hooks.slack.com/services/T000/B000/XXXX" ; "slack_webhook_ignored")]
    #[test_case("MTIzNDU2Nzg5MDEyMzQ1Njdh.GaBcDe.AbCdEfGhIjKlMnOpQrStUvWxYz0" ; "discord_segment_not_all_digits")]
    #[test_case("MTIzNDU2Nzg5MDEyMzQ1.GaBcDe.AbCdEfGhIjKlMnOpQrStUvWxYz0" ; "discord_segment_too_short")]
    #[test_case("MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GaBcDe.AbCdEfGhIjKlMnOpQrStUvWxYz012" ; "discord_hmac_between_27_and_38")]
    #[test_case("pk_live_AbCdEfGhIjKlMnOpQrStUvWx" ; "stripe_publishable")]
    #[test_case("sk_test_AbCdEfGhIjKlMnOpQrStUvWx" ; "stripe_test")]
    #[test_case("sk_live_short" ; "stripe_too_short")]
    #[test_case("shpat_0123456789abcdef0123456789abcde" ; "shopify_too_short")]
    #[test_case("sq0atp-tooshort" ; "square_too_short")]
    #[test_case(&format!("EAAA{}", filler(59)) ; "square_personal_too_short")]
    #[test_case(&format!("EAAA{}", filler(61)) ; "square_personal_too_long")]
    #[test_case("access_token$sandbox$abcdefgh12345678$0123456789abcdef0123456789abcdef" ; "braintree_sandbox")]
    #[test_case("access-sandbox-01234567-89ab-cdef-0123-456789abcdef" ; "plaid_sandbox")]
    #[test_case("SG.short.short" ; "sendgrid_too_short")]
    #[test_case("re_AbCdEfGh_AbCdEfGhJkLmNpQrStUvWxY0" ; "resend_non_base58")]
    #[test_case("pat-na1-not-a-uuid" ; "hubspot_not_uuid")]
    #[test_case(&format!("EAAM{}", filler(50)) ; "meta_too_short")]
    #[test_case(&format!("EAAC2z3BhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAAB{}", filler(100)) ; "meta_base64_font_blob")]
    #[test_case("EAAAASAAAAATBFAiEApcyBPrFl6dxkn2B4kq8LFXDdsGVHYVmYfjf2utgQLkAAA1" ; "square_base64_der_blob")]
    #[test_case("EAAAHy0AAMAQAAAgLQAAwRAAACEtAADCEAAAIi0AAMMQAAAjLQAAxBAAACQtAADFEAAAJS0A" ; "square_zero_heavy_blob")]
    #[test_case(&format!("EAACBxAAAm8QAAJ3EAAC3xAAAucQAANPEAADVxAAA78QAAPHEAAALxQAADcU{}", filler(60)) ; "meta_zero_heavy_blob")]
    #[test_case("cloudinary://<api_key>:<api_secret>@<cloud_name>" ; "cloudinary_placeholder")]
    #[test_case("cloudinary://mycloud" ; "cloudinary_no_credentials")]
    #[test_case("sntryu_0123" ; "sentry_too_short")]
    #[test_case("AUTH0_CLIENT_SECRET=process.env.AUTH0_CLIENT_SECRET" ; "auth0_env_reference")]
    #[test_case("auth0.clientSecret = 'short'" ; "auth0_too_short")]
    #[test_case("import { Auth0Client } from '@auth0/auth0-spa-js'" ; "auth0_import")]
    fn no_match(buf: &str) {
        assert_eq!(scan(buf.as_bytes()), []);
    }

    #[test_case(b"MTIzNDU2Nzg5MDEyMzQ1Njc" ; "seventeen_digits")]
    #[test_case(b"MTIzNDU2Nzg5MDEyMzQ1Njc4" ; "eighteen_digits")]
    #[test_case(b"MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.x" ; "nineteen_digits_with_tail")]
    fn snowflake_accepts(segment: &[u8]) {
        assert!(starts_with_snowflake(segment));
    }

    #[test_case(b"MTIzNDU2Nzg5MDEyMzQ1Njdh" ; "trailing_letter")]
    #[test_case(b"MTIzNDU2Nzg5MDEyMzQ1" ; "sixteen_digits")]
    #[test_case(b"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA" ; "twenty_digits")]
    #[test_case(b"MTIz.NDU2" ; "digits_after_dot_ignored")]
    #[test_case(b"" ; "empty")]
    fn snowflake_rejects(segment: &[u8]) {
        assert!(!starts_with_snowflake(segment));
    }

    #[test]
    fn discord_anchors_cover_every_three_digit_prefix() {
        for a in b'0'..=b'9' {
            for b in b'0'..=b'9' {
                for c in b'0'..=b'9' {
                    let encoded = encode_three(a, b, c);
                    assert!(
                        DISCORD_ANCHORS.contains(&encoded.as_str()),
                        "prefix of base64({}{}{}) = {encoded} missing",
                        a as char,
                        b as char,
                        c as char
                    );
                }
            }
        }
    }

    fn encode_three(a: u8, b: u8, c: u8) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let bits = u32::from_be_bytes([0, a, b, c]);
        (0..3)
            .map(|i| ALPHABET[((bits >> (18 - 6 * i)) & 0x3F) as usize] as char)
            .collect()
    }
}
