//! `pii:global:network-address` family contract v1.
//!
//! The parser is deliberately local and bounded: it implements the textual
//! IPv4 and IPv6 forms needed by the family without the standard networking
//! module. Identity is
//! separate from sensitivity. Documentation/test/benchmark space and true
//! non-endpoint constants are non-sensitive. Operational special-purpose,
//! public, private, link-local, shared, and unique-local addresses require the
//! reviewed high-signal network-address context before they are sensitive.

use super::{
    Alternative, ContextRequirement, IdentityDomain, IdentityState, PiiFamily, SensitivityState,
};
use crate::{ByteRange, Confidence, Obfuscation, Specificity};

const FAMILY_ID: &str = "pii:global:network-address";
const MAX_IPV6_TEXT_BYTES: usize = 45;

pub(super) fn family() -> Box<dyn PiiFamily> {
    Box::new(NetworkAddress)
}

struct NetworkAddress;

impl PiiFamily for NetworkAddress {
    fn id(&self) -> &'static str {
        FAMILY_ID
    }

    fn context_requirement(&self) -> ContextRequirement {
        ContextRequirement::RequiredForSensitiveClassification
    }

    fn occurrence_exclusions(&self) -> &'static [&'static str] {
        &["en-example-label", "ko-example-label"]
    }

    fn detect(&self, input: &str) -> Vec<Alternative> {
        detect_addresses(input)
    }
}

fn detect_addresses(input: &str) -> Vec<Alternative> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit()
            && ipv4_left_boundary(bytes, index)
            && let Some((end, octets)) = parse_ipv4_at(bytes, index)
            && ipv4_right_boundary(bytes, end)
        {
            let sensitive = ipv4_sensitive(octets);
            if let Some(candidate) = alternative(index, end, sensitive) {
                output.push(candidate);
            }
            index = end;
            continue;
        }
        if (is_hex(bytes[index]) || bytes[index] == b':') && ipv6_left_boundary(bytes, index) {
            let mut end = index;
            while end < bytes.len()
                && is_ipv6_body(bytes[end])
                && end - index <= MAX_IPV6_TEXT_BYTES
            {
                end += 1;
            }
            if end - index > MAX_IPV6_TEXT_BYTES {
                while end < bytes.len() && is_ipv6_body(bytes[end]) {
                    end += 1;
                }
                index = end;
                continue;
            }
            if input[index..end].contains(':')
                && ipv6_right_boundary(bytes, end)
                && let Some(address) = parse_ipv6(&input[index..end])
            {
                let sensitive = ipv6_sensitive(address);
                if let Some(candidate) = alternative(index, end, sensitive) {
                    output.push(candidate);
                }
                index = end;
                continue;
            }
        }
        index += 1;
    }
    output
}

fn alternative(start: usize, end: usize, potentially_sensitive: bool) -> Option<Alternative> {
    Some(Alternative {
        family_id: FAMILY_ID,
        domain: IdentityDomain::NetworkAddress,
        range: ByteRange::new(start, end)?,
        identity: IdentityState::Established,
        identity_confidence: Confidence::High,
        identity_specificity: Specificity::Structural,
        sensitivity: if potentially_sensitive {
            SensitivityState::NotEstablished
        } else {
            SensitivityState::NonSensitive
        },
        sensitivity_confidence: Confidence::High,
        sensitivity_specificity: Specificity::Structural,
        obfuscation: Obfuscation::None,
    })
}

fn parse_ipv4_at(bytes: &[u8], start: usize) -> Option<(usize, [u8; 4])> {
    let mut octets = [0; 4];
    let mut index = start;
    for (part, octet) in octets.iter_mut().enumerate() {
        let digit_start = index;
        let mut value: u16 = 0;
        while index < bytes.len() && bytes[index].is_ascii_digit() && index - digit_start < 3 {
            value = value * 10 + u16::from(bytes[index] - b'0');
            index += 1;
        }
        let length = index - digit_start;
        if length == 0 || value > 255 || (length > 1 && bytes[digit_start] == b'0') {
            return None;
        }
        if index < bytes.len() && bytes[index].is_ascii_digit() {
            return None;
        }
        *octet = u8::try_from(value).ok()?;
        if part < 3 {
            if bytes.get(index) != Some(&b'.') {
                return None;
            }
            index += 1;
        }
    }
    Some((index, octets))
}

fn ipv4_left_boundary(bytes: &[u8], start: usize) -> bool {
    start == 0
        || !(bytes[start - 1].is_ascii_alphanumeric()
            || matches!(bytes[start - 1], b'.' | b':' | b'_' | b'%'))
}

fn ipv4_right_boundary(bytes: &[u8], end: usize) -> bool {
    end == bytes.len()
        || !(bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'.' | b'_' | b'%'))
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_ipv6_body(byte: u8) -> bool {
    is_hex(byte) || matches!(byte, b':' | b'.')
}

fn ipv6_left_boundary(bytes: &[u8], start: usize) -> bool {
    start == 0
        || !(bytes[start - 1].is_ascii_alphanumeric()
            || matches!(bytes[start - 1], b':' | b'.' | b'_' | b'%'))
}

fn ipv6_right_boundary(bytes: &[u8], end: usize) -> bool {
    end == bytes.len()
        || !(bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b':' | b'.' | b'_' | b'%'))
}

#[derive(Clone, Copy)]
struct Ipv6 {
    units: [u16; 8],
    mapped_ipv4: Option<[u8; 4]>,
}

fn parse_ipv6(value: &str) -> Option<Ipv6> {
    if value.is_empty()
        || value.len() > MAX_IPV6_TEXT_BYTES
        || value.contains('%')
        || value.matches("::").count() > 1
    {
        return None;
    }
    let compressed = value.contains("::");
    let (left, right) = value.split_once("::").unwrap_or((value, ""));
    let mut left_storage = [0; 8];
    let mut right_storage = [0; 8];
    let (left_len, left_mapped) = parse_ipv6_side(left, &mut left_storage)?;
    let (right_len, right_mapped) = if compressed {
        parse_ipv6_side(right, &mut right_storage)?
    } else {
        (0, None)
    };
    let mapped_ipv4 = left_mapped.or(right_mapped);
    if left_mapped.is_some() && !right.is_empty() {
        return None;
    }
    let used = left_len + right_len;
    if (compressed && used >= 8) || (!compressed && used != 8) {
        return None;
    }
    let mut units = [0; 8];
    units[..left_len].copy_from_slice(&left_storage[..left_len]);
    units[8 - right_len..].copy_from_slice(&right_storage[..right_len]);
    Some(Ipv6 { units, mapped_ipv4 })
}

fn parse_ipv6_side(value: &str, units: &mut [u16; 8]) -> Option<(usize, Option<[u8; 4]>)> {
    if value.is_empty() {
        return Some((0, None));
    }
    let mut length = 0;
    let mut mapped = None;
    let mut groups = value.split(':').peekable();
    while let Some(group) = groups.next() {
        if group.is_empty() {
            return None;
        }
        if group.contains('.') {
            if groups.peek().is_some() || mapped.is_some() || length > 6 {
                return None;
            }
            let (end, octets) = parse_ipv4_at(group.as_bytes(), 0)?;
            if end != group.len() {
                return None;
            }
            units[length] = (u16::from(octets[0]) << 8) | u16::from(octets[1]);
            units[length + 1] = (u16::from(octets[2]) << 8) | u16::from(octets[3]);
            length += 2;
            mapped = Some(octets);
        } else {
            if length == 8 || group.len() > 4 || !group.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return None;
            }
            units[length] = u16::from_str_radix(group, 16).ok()?;
            length += 1;
        }
    }
    Some((length, mapped))
}

fn ipv4_sensitive(o: [u8; 4]) -> bool {
    if o == [0, 0, 0, 0]
        || o[0] == 127
        || (224..=239).contains(&o[0])
        || o == [255, 255, 255, 255]
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return false;
    }
    true
}

fn ipv6_sensitive(address: Ipv6) -> bool {
    if let Some(ipv4) = address.mapped_ipv4
        && address.units[..6] == [0, 0, 0, 0, 0, 0xffff]
    {
        return ipv4_sensitive(ipv4);
    }
    let u = address.units;
    if u == [0; 8]
        || u == [0, 0, 0, 0, 0, 0, 0, 1]
        || u[0] & 0xff00 == 0xff00
        || (u[0] == 0x2001 && u[1] == 0x0db8)
        || (u[0] == 0x2001 && u[1] == 0x0002 && u[2] == 0)
        || (u[0] == 0x3fff && u[1] & 0xf000 == 0)
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_ipv4_and_ipv6_text_without_zone_ids() {
        assert_eq!(
            parse_ipv4_at(b"203.0.113.9", 0),
            Some((11, [203, 0, 113, 9]))
        );
        assert!(parse_ipv4_at(b"01.2.3.4", 0).is_none());
        assert!(parse_ipv6("2001:db8::1").is_some());
        let link_local = detect_addresses("client_ip=fe80::1");
        assert_eq!(link_local.len(), 1);
        let contexts = super::super::context_matches(
            "client_ip=fe80::1",
            &[(link_local[0].range, IdentityDomain::NetworkAddress)],
        );
        assert!(!contexts[0].is_empty());
        assert!(parse_ipv6("::ffff:192.0.2.1").is_some());
        assert!(parse_ipv6("fe80::1%eth0").is_none());
        assert!(parse_ipv6("2001::db8::1").is_none());
        assert!(detect_addresses("client_ip=xfd00::1").is_empty());
        assert!(detect_addresses("client_ip=fd00::1z").is_empty());
        assert!(detect_addresses("client_ip=192.168.1.7suffix").is_empty());
        assert!(detect_addresses("release v192.168.1.7").is_empty());
        assert_eq!(
            detect_addresses("client_ip=http://192.168.1.7:443/").len(),
            1
        );
        assert!(parse_ipv6(&format!("{}::1", "a".repeat(46))).is_none());
        assert!(detect_addresses(&format!("client_ip={}::1", "a".repeat(46))).is_empty());
        let mapped = detect_addresses("source_ip=::ffff:192.168.1.7");
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].range, ByteRange::new(10, 28).unwrap());
    }

    #[test]
    fn classifies_reviewed_address_classes() {
        assert!(!ipv4_sensitive([192, 0, 2, 1]));
        assert!(!ipv4_sensitive([127, 0, 0, 1]));
        assert!(ipv4_sensitive([100, 64, 0, 1]));
        assert!(!ipv4_sensitive([198, 18, 0, 1]));
        assert!(!ipv4_sensitive([239, 1, 1, 1]));
        assert!(ipv4_sensitive([10, 0, 0, 1]));
        assert!(ipv4_sensitive([172, 16, 0, 1]));
        assert!(!ipv6_sensitive(parse_ipv6("2001:db8::1").unwrap()));
        assert!(!ipv6_sensitive(parse_ipv6("::1").unwrap()));
        assert!(ipv6_sensitive(parse_ipv6("fe80::1").unwrap()));
        assert!(!ipv6_sensitive(parse_ipv6("ff02::1").unwrap()));
        assert!(ipv6_sensitive(parse_ipv6("2001:20::1").unwrap()));
        assert!(!ipv6_sensitive(parse_ipv6("2001:2::1").unwrap()));
        assert!(ipv6_sensitive(parse_ipv6("2001:2:1::1").unwrap()));
        assert!(!ipv6_sensitive(parse_ipv6("3fff:0::1").unwrap()));
        assert!(ipv6_sensitive(parse_ipv6("3fff:1000::1").unwrap()));
        assert!(ipv6_sensitive(parse_ipv6("fd00::1").unwrap()));
        assert_eq!(
            ipv6_sensitive(parse_ipv6("::ffff:192.168.1.7").unwrap()),
            ipv4_sensitive([192, 168, 1, 7])
        );
    }
}
