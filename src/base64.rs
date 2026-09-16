//! Base64 support for matching secrets inside encoded blobs: derives the
//! encoded literals an anchor produces at each byte alignment, and decodes
//! bounded runs around a hit.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Shorter encoded literals are too common in ordinary base64 to anchor on.
const MIN_LITERAL_LEN: usize = 4;
/// Encoded characters fully determined by the anchor: skipped at the start
/// per byte alignment, kept at the end per trailing byte count.
const LEADING_SKIP: [usize; 3] = [0, 2, 3];
const TRAILING_KEEP: [usize; 3] = [0, 1, 2];

/// An anchor as it appears inside base64 text, at one byte alignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAnchor {
    pub literal: Vec<u8>,
    /// Byte offset of the anchor within its first 3-byte group.
    pub alignment: usize,
    /// Encoded characters between that group's start and the literal.
    pub skip: usize,
}

/// Every literal `anchor` can produce inside base64 text, in both the
/// standard and URL-safe alphabets, long enough to be worth anchoring on.
pub fn encoded_anchors(anchor: &[u8]) -> Vec<EncodedAnchor> {
    let mut out = Vec::new();
    for (alignment, &start) in LEADING_SKIP.iter().enumerate() {
        let mut padded = vec![0u8; alignment];
        padded.extend_from_slice(anchor);
        let encoded = encode(&padded);
        let end = padded.len() / 3 * 4 + TRAILING_KEEP[padded.len() % 3];
        if end.saturating_sub(start) < MIN_LITERAL_LEN {
            continue;
        }
        let literal = encoded[start..end].to_vec();
        let url_safe: Vec<u8> = literal
            .iter()
            .map(|&byte| match byte {
                b'+' => b'-',
                b'/' => b'_',
                other => other,
            })
            .collect();
        if url_safe != literal {
            out.push(EncodedAnchor {
                literal: url_safe,
                alignment,
                skip: start,
            });
        }
        out.push(EncodedAnchor {
            literal,
            alignment,
            skip: start,
        });
    }
    out
}

pub fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// Decodes `text` (either alphabet, padding optional) into `out`, stopping at
/// the first byte outside the alphabet.
pub fn decode_into(text: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in text {
        let Some(sextet) = sextet(byte) else {
            break;
        };
        acc = (acc << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or_default());
            acc &= (1 << bits) - 1;
        }
    }
}

fn encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        let chars = chunk.len() * 4 / 3 + usize::from(chunk.len() % 3 != 0);
        for i in 0..chars {
            out.push(ALPHABET[((bits >> (18 - 6 * i)) & 0x3F) as usize]);
        }
    }
    out
}

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::{EncodedAnchor, decode_into, encode, encoded_anchors};

    #[test_case(b"", b"" ; "empty")]
    #[test_case(b"f", b"Zg" ; "one_byte")]
    #[test_case(b"fo", b"Zm8" ; "two_bytes")]
    #[test_case(b"foo", b"Zm9v" ; "three_bytes")]
    #[test_case(b"ghp_", b"Z2hwXw" ; "four_bytes")]
    fn encodes_without_padding(input: &[u8], expected: &[u8]) {
        assert_eq!(encode(input), expected);
    }

    #[test_case(b"Zm9v", b"foo" ; "standard")]
    #[test_case(b"Zm9vYg==", b"foob" ; "padded")]
    #[test_case(b"Zm9vYg", b"foob" ; "unpadded")]
    #[test_case(b"-_-_", b"\xfb\xff\xbf" ; "url_safe_alphabet")]
    #[test_case(b"Zm9v\nYg", b"foo" ; "stops_at_invalid_byte")]
    fn decodes(input: &[u8], expected: &[u8]) {
        let mut out = Vec::new();
        decode_into(input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn literal_is_stable_across_surrounding_bytes() {
        for anchor in encoded_anchors(b"ghp_") {
            let mut bytes = vec![b'x'; anchor.alignment];
            bytes.extend_from_slice(b"ghp_ABC");
            let encoded = encode(&bytes);
            assert_eq!(
                &encoded[anchor.skip..anchor.skip + anchor.literal.len()],
                anchor
                    .literal
                    .iter()
                    .map(|&b| match b {
                        b'-' => b'+',
                        b'_' => b'/',
                        other => other,
                    })
                    .collect::<Vec<_>>(),
                "alignment {}",
                anchor.alignment
            );
        }
    }

    #[test]
    fn four_byte_anchor_yields_three_alignments() {
        let anchors = encoded_anchors(b"AKIA");
        let literals: Vec<_> = anchors.iter().map(|a| a.literal.as_slice()).collect();
        assert_eq!(literals, [&b"QUtJQ"[..], b"FLSU", b"BS0lB"]);
        assert_eq!(
            anchors[1],
            EncodedAnchor {
                literal: b"FLSU".to_vec(),
                alignment: 1,
                skip: 2,
            }
        );
    }

    #[test]
    fn url_safe_variant_added_when_alphabets_differ() {
        let anchors = encoded_anchors(b"~~~~~~");
        let has_plus_or_slash = anchors
            .iter()
            .any(|a| a.literal.contains(&b'+') || a.literal.contains(&b'/'));
        let has_url_safe = anchors
            .iter()
            .any(|a| a.literal.contains(&b'-') || a.literal.contains(&b'_'));
        assert!(has_plus_or_slash && has_url_safe);
    }

    #[test]
    fn three_byte_anchor_yields_only_aligned_form() {
        let anchors = encoded_anchors(b"re_");
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].literal, b"cmVf");
    }
}
