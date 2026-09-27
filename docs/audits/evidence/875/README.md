# Issue #875 — network-address family contract v1

This is the frozen product judgment for the first production PII family. It
applies the accepted PII domain and `pii-v1` qualification policies; it does
not create a new workspace-wide policy or claim stable support.

## Identity

IPv4 and IPv6 are two textual variants of one canonical family, not two
support rows:

| Field | Frozen value |
| --- | --- |
| Family | `pii:global:network-address` |
| Family contract | `1` |
| Identity domain | `network-address` |
| Exact selector | `pii:family:global:network-address` |
| Public type | `pii_global_network_address` |
| Adapter | `pii-domain` (the single PII detector slot) |
| Scope | `global` |
| Qualification profile | `pii-v1` version 1 |
| Context obligation | `required-for-sensitive-classification` |
| Activation availability | `full` and `common`, explicit opt-in only |

One family avoids manufacturing ambiguity when an IPv4 address is written in
the IPv4-embedded IPv6 form. The bounded parser accepts canonical dotted
decimal IPv4 (four decimal octets, 0–255, no leading zero on a multi-digit
octet), full or compressed IPv6, and a final dotted-decimal IPv4 component.
It rejects zone identifiers. ASCII address boundaries prevent a valid suffix
inside a longer malformed address from becoming a finding. Brackets are not
part of the range.

The lexical authority is [RFC 791 section 3.1](https://www.rfc-editor.org/rfc/rfc791#section-3.1)
for the 32-bit IPv4 address and [RFC 4291 section 2.2](https://www.rfc-editor.org/rfc/rfc4291#section-2.2)
for IPv6 text, compression, and embedded IPv4. `sourceKind` is `standard`,
`sourceId` is `rfc-791` or `rfc-4291`, `revision` is `1981-09` or `2006-02`,
and `supports` is `lexical` and `validation` respectively.

## Sensitivity and exclusions

Parsing establishes identity only. Public/global-unicast, RFC 1918 private,
RFC 4193 unique-local, link-local, shared CGNAT, Teredo, translation, ORCHID,
and other operational special-purpose addresses become sensitive only when an
associated high-signal English or Korean network-address field label satisfies
`pii-context/v1`. IANA allocation/routing metadata is not authority that an
address occurrence is non-personal. A URL host remains identity-valid, but URL
syntax does not bridge the field-label grammar, so an uncontextualized host
remains `not-established`; URL wrapping itself is not negative evidence.

Contract v1 makes only these whole address classes non-sensitive, even beside
a positive label:

- IPv4 `0.0.0.0`, loopback `127.0.0.0/8`, multicast `224.0.0.0/4`, and
  limited broadcast `255.255.255.255` (true non-endpoint constants/classes);
- RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`;
- RFC 2544 benchmarking `198.18.0.0/15`;
- IPv6 `::`, `::1`, and multicast `ff00::/8`;
- RFC 3849 `2001:db8::/32`, BMWG benchmarking `2001:2::/48`, and RFC 9637
  documentation `3fff::/20`; and
- an IPv4-mapped IPv6 address exactly under `::ffff:0:0/96` inherits the
  embedded IPv4 class.

Multicast is non-sensitive because it denotes a receiver group rather than an
individual endpoint; this is a project sensitivity rule, not inferred from
IANA's special-purpose label. `documentation`/`example` and Korean `예시` remain the
named associated negative contexts. `v`/`V` followed immediately by a dotted
quad is the named whole-candidate version collision grammar and is unmatched,
so no address identity or sensitivity result is manufactured from a suffix.

Reserved-control authority is [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737),
[RFC 3849](https://www.rfc-editor.org/rfc/rfc3849), and the IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
special-purpose registries. RFC 2544, RFC 3849, RFC 5737, and RFC 9637 support
the frozen negative controls. RFC 1918, RFC 4193, and link-local ranges are
safe synthetic positive inputs only; they do not assert that every
private/local address identifies a person.

## Trade-offs

Requiring context prevents bare addresses, dotted versions, ordinary numeric
collisions, and unlabelled URL hosts from being treated as personal data. It
intentionally misses a sensitive address without a reviewed label, a zone-id
form, and an address expressed in an unsupported non-canonical IPv4 spelling.
The detector performs no allocation lookup and no runtime I/O.

All committed examples use only official documentation, reserved, private,
or local ranges. Exact-candidate benchmark evidence and the generated status
row are owned by `redact-secret-benchmarks#388`; until those gates pass, the
row remains `pending` and this repository makes no provisional support claim.
