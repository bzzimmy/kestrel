use crate::rules::Rule;

pub const RULES: &[Rule] = &[
    Rule {
        id: "openai-api-key",
        anchors: &["T3BlbkFJ"],
        pattern: r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,74}T3BlbkFJ[A-Za-z0-9_-]{20,74}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "anthropic-api-key",
        anchors: &["sk-ant-api03-", "sk-ant-admin01-"],
        pattern: r"\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA)(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "openrouter-api-key",
        anchors: &["sk-or-v1-"],
        pattern: r"\bsk-or-v1-[a-f0-9]{64}\b",
        verify: None,
    },
    Rule {
        id: "gemini-api-key",
        anchors: &["AQ.Ab8RN6"],
        pattern: r"\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "groq-api-key",
        anchors: &["gsk_"],
        pattern: r"\bgsk_[A-Za-z0-9]{52}\b",
        verify: None,
    },
    Rule {
        id: "xai-api-key",
        anchors: &["xai-"],
        pattern: r"\b(xai-[A-Za-z0-9_-]{70,120})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "perplexity-api-key",
        anchors: &["pplx-"],
        pattern: r"\bpplx-[A-Za-z0-9]{48}\b",
        verify: None,
    },
    Rule {
        id: "replicate-api-token",
        anchors: &["r8_"],
        pattern: r"\br8_[A-Za-z0-9]{37}\b",
        verify: None,
    },
    Rule {
        id: "together-api-key",
        anchors: &["tgp_v1_"],
        pattern: r"\b(tgp_v1_[A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|\z)",
        verify: None,
    },
    Rule {
        id: "cerebras-api-key",
        anchors: &["csk-"],
        pattern: r"\bcsk-[a-z0-9]{48}\b",
        verify: None,
    },
    Rule {
        id: "runpod-api-key",
        anchors: &["rpa_"],
        pattern: r"\brpa_[A-Z0-9]{40}[A-Za-z0-9]{6}\b",
        verify: None,
    },
    Rule {
        id: "elevenlabs-api-key",
        anchors: &["sk_"],
        pattern: r"\bsk_[a-f0-9]{48}\b",
        verify: None,
    },
    Rule {
        id: "huggingface-token",
        anchors: &["hf_"],
        pattern: r"\bhf_[A-Za-z]{34}\b",
        verify: None,
    },
    Rule {
        id: "deepseek-api-key",
        anchors: &["deepseek", "DeepSeek", "DEEPSEEK_API_KEY"],
        pattern: r#"(?:deepseek|DeepSeek|DEEPSEEK_API_KEY)[^\n=:]{0,16}[=:]>?\s{0,8}["'`]?(sk-[a-f0-9]{32})(?:[^A-Za-z0-9_-]|\z)"#,
        verify: None,
    },
];

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::RULES;

    const OPENAI: &str = "openai-api-key";
    const ANTHROPIC: &str = "anthropic-api-key";
    const OPENROUTER: &str = "openrouter-api-key";
    const GEMINI: &str = "gemini-api-key";
    const GROQ: &str = "groq-api-key";
    const XAI: &str = "xai-api-key";
    const PERPLEXITY: &str = "perplexity-api-key";
    const REPLICATE: &str = "replicate-api-token";
    const TOGETHER: &str = "together-api-key";
    const CEREBRAS: &str = "cerebras-api-key";
    const RUNPOD: &str = "runpod-api-key";
    const ELEVENLABS: &str = "elevenlabs-api-key";
    const HUGGINGFACE: &str = "huggingface-token";
    const DEEPSEEK: &str = "deepseek-api-key";

    const HEX32: &str = "0123456789abcdef0123456789abcdef";
    const HEX48: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OPENAI_LEGACY: &str = "sk-AbCdEfGhIjKlMnOpQrStT3BlbkFJAbCdEfGhIjKlMnOpQrSt";
    const GROQ_KEY: &str = "gsk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp";
    const PPLX_KEY: &str = "pplx-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl";
    const R8_KEY: &str = "r8_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789A";
    const HF_KEY: &str = "hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh";
    const CSK_KEY: &str = "csk-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl";
    const RPA_KEY: &str = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDaBcD12";

    fn scan(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
        crate::rules::scan(RULES, buf)
    }

    fn repeat(byte: u8, count: usize) -> String {
        String::from_utf8(vec![byte; count]).unwrap_or_default()
    }

    #[test_case(&format!("OPENAI_API_KEY=sk-proj-{}T3BlbkFJ{}", repeat(b'a', 74), repeat(b'b', 74)), OPENAI, &format!("sk-proj-{}T3BlbkFJ{}", repeat(b'a', 74), repeat(b'b', 74)) ; "openai_project_long")]
    #[test_case(&format!("sk-proj-{}T3BlbkFJ{}", repeat(b'a', 20), repeat(b'b', 20)), OPENAI, &format!("sk-proj-{}T3BlbkFJ{}", repeat(b'a', 20), repeat(b'b', 20)) ; "openai_project_short")]
    #[test_case(&format!("\"sk-svcacct-{}T3BlbkFJ{}\"", repeat(b'a', 58), repeat(b'b', 58)), OPENAI, &format!("sk-svcacct-{}T3BlbkFJ{}", repeat(b'a', 58), repeat(b'b', 58)) ; "openai_service_account")]
    #[test_case(&format!("sk-admin-{}T3BlbkFJ{}", repeat(b'a', 74), repeat(b'b', 74)), OPENAI, &format!("sk-admin-{}T3BlbkFJ{}", repeat(b'a', 74), repeat(b'b', 74)) ; "openai_admin")]
    #[test_case(&format!("apiKey: '{OPENAI_LEGACY}'"), OPENAI, OPENAI_LEGACY ; "openai_legacy")]
    #[test_case(&format!("ANTHROPIC_API_KEY=sk-ant-api03-{}AA\n", repeat(b'a', 93)), ANTHROPIC, &format!("sk-ant-api03-{}AA", repeat(b'a', 93)) ; "anthropic_api")]
    #[test_case(&format!("sk-ant-admin01-{}AA", repeat(b'a', 93)), ANTHROPIC, &format!("sk-ant-admin01-{}AA", repeat(b'a', 93)) ; "anthropic_admin")]
    #[test_case(&format!("Authorization: Bearer sk-or-v1-{HEX64}"), OPENROUTER, &format!("sk-or-v1-{HEX64}") ; "openrouter")]
    #[test_case(&format!("GEMINI_API_KEY=AQ.Ab8RN6{}", repeat(b'a', 44)), GEMINI, &format!("AQ.Ab8RN6{}", repeat(b'a', 44)) ; "gemini")]
    #[test_case(&format!("groq = Groq(api_key=\"{GROQ_KEY}\")"), GROQ, GROQ_KEY ; "groq")]
    #[test_case(&format!("XAI_API_KEY=xai-{}", repeat(b'a', 80)), XAI, &format!("xai-{}", repeat(b'a', 80)) ; "xai")]
    #[test_case(&format!("{{\"key\": \"{PPLX_KEY}\"}}"), PERPLEXITY, PPLX_KEY ; "perplexity")]
    #[test_case(&format!("REPLICATE_API_TOKEN={R8_KEY}"), REPLICATE, R8_KEY ; "replicate")]
    #[test_case(&format!("tgp_v1_{}", repeat(b'a', 43)), TOGETHER, &format!("tgp_v1_{}", repeat(b'a', 43)) ; "together")]
    #[test_case(&format!("CEREBRAS_API_KEY={CSK_KEY}"), CEREBRAS, CSK_KEY ; "cerebras")]
    #[test_case(&format!("runpod.api_key = \"{RPA_KEY}\""), RUNPOD, RPA_KEY ; "runpod")]
    #[test_case(&format!("xi-api-key: sk_{HEX48}"), ELEVENLABS, &format!("sk_{HEX48}") ; "elevenlabs")]
    #[test_case(&format!("HF_TOKEN={HF_KEY}"), HUGGINGFACE, HF_KEY ; "huggingface")]
    #[test_case(&format!("DEEPSEEK_API_KEY=sk-{HEX32}"), DEEPSEEK, &format!("sk-{HEX32}") ; "deepseek_env")]
    #[test_case(&format!("deepseek_api_key: \"sk-{HEX32}\""), DEEPSEEK, &format!("sk-{HEX32}") ; "deepseek_yaml")]
    #[test_case(&format!("new DeepSeek({{ apiKey: 'sk-{HEX32}' }})"), DEEPSEEK, &format!("sk-{HEX32}") ; "deepseek_constructor")]
    fn single_match(buf: &str, rule_id: &'static str, secret: &str) {
        assert_eq!(scan(buf.as_bytes()), [(rule_id, secret.as_bytes())]);
    }

    #[test_case(&format!("sk-proj-{}", repeat(b'a', 100)) ; "openai_no_watermark")]
    #[test_case(&format!("sk-proj-{}T3BlbkFJ{}", repeat(b'a', 74), repeat(b'b', 10)) ; "openai_suffix_too_short")]
    #[test_case("sk-AbCdEfGhIjT3BlbkFJAbCdEfGhIj" ; "openai_legacy_too_short")]
    #[test_case(&format!("sk-ant-api03-{}AA", repeat(b'a', 92)) ; "anthropic_too_short")]
    #[test_case(&format!("sk-ant-api03-{}AB", repeat(b'a', 93)) ; "anthropic_wrong_suffix")]
    #[test_case(&format!("sk-or-v1-{HEX48}") ; "openrouter_too_short")]
    #[test_case(&format!("sk-or-v1-{}", repeat(b'g', 64)) ; "openrouter_not_hex")]
    #[test_case("AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789" ; "gemini_legacy_aiza")]
    #[test_case(&format!("AQ.Ab8RN6{}", repeat(b'a', 43)) ; "gemini_too_short")]
    #[test_case("gsk_short" ; "groq_too_short")]
    #[test_case(&format!("xai-{}", repeat(b'a', 69)) ; "xai_too_short")]
    #[test_case(&format!("xai-{}", repeat(b'a', 121)) ; "xai_too_long")]
    #[test_case("pplx-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" ; "perplexity_too_short")]
    #[test_case("r8_AbCdEfGhIjKlMnOpQrStUvWxYz01234567" ; "replicate_too_short")]
    #[test_case(&format!("tgp_v1_{}", repeat(b'a', 42)) ; "together_too_short")]
    #[test_case("csk-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk" ; "cerebras_too_short")]
    #[test_case("csk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL" ; "cerebras_uppercase")]
    #[test_case("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDaBcD1" ; "runpod_too_short")]
    #[test_case("rpa_abcdefghijklmnopqrstuvwxyz0123456789ABCDaBcD12" ; "runpod_lowercase_body")]
    #[test_case("sk_live_AbCdEfGhIjKlMnOpQrStUvWx" ; "elevenlabs_ignores_stripe")]
    #[test_case(&format!("sk_{HEX32}") ; "elevenlabs_too_short")]
    #[test_case(&format!("sk_{}", repeat(b'A', 48)) ; "elevenlabs_not_hex")]
    #[test_case("hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567" ; "huggingface_digits")]
    #[test_case("hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfG" ; "huggingface_too_short")]
    #[test_case(&format!("sk-{HEX32}") ; "deepseek_no_keyword")]
    #[test_case("DEEPSEEK_API_KEY=process.env.DEEPSEEK_API_KEY" ; "deepseek_env_reference")]
    #[test_case(&format!("DEEPSEEK_API_KEY=sk-{HEX48}") ; "deepseek_too_long")]
    #[test_case("deepseek_api_key: 'sk-tooshort'" ; "deepseek_too_short")]
    fn no_match(buf: &str) {
        assert_eq!(scan(buf.as_bytes()), []);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let buf = format!("{OPENAI_LEGACY}\n{GROQ_KEY} {R8_KEY}\n{HF_KEY}");
        assert_eq!(
            scan(buf.as_bytes()),
            [
                (OPENAI, OPENAI_LEGACY.as_bytes()),
                (GROQ, GROQ_KEY.as_bytes()),
                (REPLICATE, R8_KEY.as_bytes()),
                (HUGGINGFACE, HF_KEY.as_bytes()),
            ]
        );
    }
}
