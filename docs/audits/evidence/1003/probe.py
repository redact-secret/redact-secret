#!/usr/bin/env python3
"""Deterministic public probe matrix for the us-ssn identity-only gap (#1003).

Feeds synthetic inputs through the product identity seam
(`pii_identity_evaluation` example, `--family pii:us:ssn`) and compares each
line with an expectation derived ONLY from docs/contracts/pii/us-ssn-v1.md.

Usage (two steps, no subprocess: the example reads JSON lines on stdin):

    probe.py emit | <path-to-example-binary> --family pii:us:ssn > out.jsonl
    probe.py check out.jsonl [--all]

Prints one JSON line per disagreement (every row with --all). No real SSN is
used: every value is a synthetic fixture value, an SSA invalid-by-design
control, or a long-public advertising/placeholder number that the contract
does not treat specially. A `None` context expectation means the contract
text fixes only the identity outcome for that shape.
"""
import json
import re
import sys

VALID = "890626879"  # synthetic public fixture value
FORMS = {
    "compact": lambda c: c,
    "hyphen": lambda c: f"{c[:3]}-{c[3:5]}-{c[5:]}",
    "space": lambda c: f"{c[:3]} {c[3:5]} {c[5:]}",
    "dot": lambda c: f"{c[:3]}.{c[3:5]}.{c[5:]}",
    "slash": lambda c: f"{c[:3]}/{c[3:5]}/{c[5:]}",
    "unicode-dash": lambda c: f"{c[:3]}‐{c[3:5]}‐{c[5:]}",
    "en-dash": lambda c: f"{c[:3]}–{c[3:5]}–{c[5:]}",
    "fullwidth-digits": lambda c: "".join(chr(0xFF10 + int(d)) for d in c),
    "last4-masked": lambda c: f"***-**-{c[5:]}",
    "partial-hyphen": lambda c: f"{c[:3]}-{c[3:]}",
}
VALUES = {
    "valid-synthetic": VALID,
    "placeholder-123-45-6789": "123456789",
    "placeholder-111-11-1111": "111111111",
    "placeholder-078-05-1120": "078051120",
    "placeholder-219-09-9999": "219099999",
    "area-000": "000626879",
    "area-666": "666626879",
    "area-900": "900626879",
    "area-899": "899626879",
    "area-999": "999626879",
    "area-987-ad-range": "987654320",
    "group-00": "890006879",
    "serial-0000": "890620000",
    "all-zero-control": "000000000",
    "area-001-edge": "001010001",
    "area-665-edge": "665999999",
    "area-667-edge": "667010001",
    "area-899-edge": "899999999",
}
S, N, X = "sensitive", "not-established", "non-sensitive"
# "Social Security Number is " and "미국 사회보장번호는 " are N, not S: the contract
# counts only a bounded field label (a trailing "is" / particle is not one).
CONTEXTS = [
    ("", N), ("ssn=", S), ("SSN: ", S), ("Ssn ", S), ("social security number: ", S),
    ("Social Security Number is ", N), ("social_security_number=", S),
    ("사회보장번호: ", S), ("사회 보장 번호 = ", S), ("미국 사회보장번호는 ", N),
    ("사회보장번호=", S), ("미국 사회보장번호: ", S),
    ("주민등록번호: ", N), ("tax id: ", N), ("national id: ", N), ("order_reference=", N),
    ("invoice number ", N), ("number: ", N), ("id=", N), ("test ssn is ", None),
    ("not ssn: ", X), ("not_ssn=", X), ("ssn example=", X), ("ssn documentation=", X),
    ("example ssn: ", X), ("사회보장번호 예시: ", X), ("사회보장번호_아님=", X),
    ("사회보장번호 아님: ", X), ("예시 사회보장번호: ", X), ("documentation ssn=", X),
    ("ssn (example): ", None), ("ssn placeholder=", None), ("fake ssn: ", None),
    ("sample ssn=", None), ("dummy ssn=", None), ("test_ssn=", None),
]
BOUNDS = [
    ("sentence-end", "ssn: ", "."), ("comma", "ssn: ", ","), ("paren", "ssn: (", ")"),
    ("quote", 'ssn: "', '"'), ("newline-after", "ssn: ", "\nnext"), ("tab-before", "ssn:\t", ""),
    ("slash-after", "ssn: ", "/x"), ("colon-after", "ssn: ", ":x"), ("semicolon", "ssn=", ";"),
    ("hyphen-after", "ssn: ", "-1"), ("hyphen-before", "ssn: 1-", ""),
    ("dot-digit-after", "ssn: ", ".5"), ("comma-digit-after", "ssn: ", ",1"),
    ("nbsp-before", "ssn: ", ""), ("ideographic-space-before", "사회보장번호:　", ""),
    ("ideographic-space-after", "사회보장번호: ", "　끝"),
    ("korean-letter-after", "사회보장번호 ", "입니다"), ("korean-letter-before", "번호", ""),
    ("korean-particle-after", "ssn=", "은"), ("fullwidth-colon", "ssn：", ""),
    ("cr-lf", "ssn:\r\n", "\r\n"), ("url-query", "https://x.invalid/?ssn=", "&a=1"),
    ("json", '{"ssn":"', '"}'), ("two-ssns", "ssn: ", " 123-45-6789"),
]


def contract_identity(text, start, end):
    """Established iff the slice is a whole ASCII compact/display form with a
    valid structure and permitted boundaries (contract text only)."""
    s = text[start:end]
    m = re.fullmatch(r"(\d{3})(\d{2})(\d{4})", s) or re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", s)
    if not m or not s.isascii():
        return "unmatched"
    a, g, n = m.groups()
    if a in ("000", "666") or int(a) >= 900 or g == "00" or n == "0000":
        return "unmatched"
    left = text[start - 1] if start else ""
    right = text[end] if end < len(text) else ""
    for ch in (left, right):
        if ch and (ch.isalnum() or ch in "_%-" or (ch.isspace() and not ch.isascii())):
            return "unmatched"
    pre, post = text[:start], text[end:]
    if (pre.endswith("{{") and post.startswith("}}")) or (
        pre.endswith("${") and post.startswith("}")) or (
        pre.endswith("<") and post.startswith(">")):
        return "unmatched"
    return "established"


def build():
    cases = []
    for vlabel, comp in VALUES.items():
        for flabel, fn in FORMS.items():
            if flabel not in ("compact", "hyphen") and vlabel not in (
                    "valid-synthetic", "placeholder-123-45-6789", "area-000"):
                continue
            v = fn(comp)
            b = len("ssn=")
            cases.append((f"value/{vlabel}/{flabel}/ssn", "ssn=" + v, (b, b + len(v.encode())), S, "value-form"))
            cases.append((f"value/{vlabel}/{flabel}/bare", v, (0, len(v.encode())), N, "value-form"))
    for clabel, exp in CONTEXTS:
        name = clabel.strip() or "none"
        for flabel in ("compact", "hyphen"):
            v = FORMS[flabel](VALID)
            b = len(clabel.encode())
            cases.append((f"context/{name}/{flabel}", clabel + v, (b, b + len(v.encode())), exp, "context"))
        v = FORMS["hyphen"](VALID)
        cases.append((f"context-after/{name}", v + " " + clabel.strip(), (0, len(v.encode())), None, "context-after"))
        prefix = clabel.strip() + "\n"
        cases.append((f"context-prev-line/{name}", prefix + v,
                      (len(prefix.encode()), len(prefix.encode()) + len(v.encode())), None, "context-prev-line"))
    for name, left, right in BOUNDS:
        for flabel in ("compact", "hyphen"):
            v = FORMS[flabel](VALID)
            b = len(left.encode())
            cases.append((f"boundary/{name}/{flabel}", left + v + right, (b, b + len(v.encode())), None, "boundary"))
    base = "ssn=890-62-6879"
    for label, rng in {"whole": (4, 15), "without-last-digit": (4, 14), "with-leading-label": (0, 15),
                       "empty": (4, 4), "past-end": (4, 99)}.items():
        cases.append((f"range/{label}", base, rng, None, "range"))
    cases.append(("range/null", base, None, None, "range"))
    return cases


def expected(text, cand):
    if cand is None:
        return "unmatched"
    raw = text.encode()
    try:
        pre = raw[:cand[0]].decode()
        mid = raw[cand[0]:cand[1]].decode()
        post = raw[cand[1]:].decode()
    except UnicodeDecodeError:
        return "unmatched"
    if cand[1] > len(raw) or cand[0] > cand[1]:
        return "unmatched"
    return contract_identity(pre + mid + post, len(pre), len(pre) + len(mid))


def emit(cases):
    for c in cases:
        print(json.dumps({"id": c[0], "family": "pii:us:ssn", "text": c[1],
                          "candidate": None if c[2] is None else {"start": c[2][0], "end": c[2][1]}},
                         ensure_ascii=False))


def check(cases, path, show_all):
    with open(path, encoding="utf-8") as handle:
        out = handle.read().splitlines()[1:]  # the first line is the example's header
    if len(out) != len(cases):
        sys.exit(f"expected {len(cases)} result lines, got {len(out)}")
    bad_count = 0
    for (cid, text, cand, ctx, group), line in zip(cases, out):
        r = json.loads(line)
        exp_id = expected(text, cand)
        exp_sens = "not-established" if exp_id == "unmatched" else ctx
        bad = r["identity"] != exp_id or (exp_sens is not None and r["sensitivity"] != exp_sens)
        bad_count += bad
        if bad or show_all:
            print(json.dumps({"id": cid, "group": group, "identity": r["identity"],
                              "expectedIdentity": exp_id, "sensitivity": r["sensitivity"],
                              "expectedSensitivity": exp_sens, "disagree": bad}, ensure_ascii=False))
    print(f"# cases={len(cases)} disagreements={bad_count}", file=sys.stderr)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("emit", "check"):
        sys.exit("usage: probe.py emit | probe.py check <results.jsonl> [--all]")
    cases = build()
    if sys.argv[1] == "emit":
        emit(cases)
    else:
        if len(sys.argv) < 3:
            sys.exit("usage: probe.py check <results.jsonl> [--all]")
        check(cases, sys.argv[2], "--all" in sys.argv)


main()
