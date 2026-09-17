/**
 * A deterministic stand-in for `scanAndRedact`, shaped exactly like the real
 * result (`{ text, findings }`, `finding.action`). Self-contained rather
 * than imported from `examples/tracing-masking/fixtures/fake-scanner.mjs` —
 * each example directory stands on its own — but implements the same four
 * rules, by convention, so a reader who has seen one recognizes the other:
 *
 * - text containing `BOOM` throws (a simulated core failure).
 * - text containing `BLOCK_ME` gets a `block` finding.
 * - text matching `SECRET_TOKEN_\d+` gets one `redact` finding over that
 *   span.
 * - text containing `WARN_ME` gets a `warn` finding (left untouched).
 * - anything else has no findings.
 *
 * Kept in sync by hand with `python/fixtures/fake_scanner.py`; both
 * implement the same four rules so `fixtures/mcp-redact-cases.json` means
 * the same thing in either language.
 */

function finding(action) {
  return {
    id: "finding-1",
    type: "generic_token",
    detector: "fake",
    confidence: action === "warn" ? "medium" : "high",
    action,
    start: 0,
    end: 0,
  };
}

export function fakeScanAndRedact(text) {
  if (text.includes("BOOM")) {
    throw new Error("simulated core failure - must never surface to a caller");
  }
  if (text.includes("BLOCK_ME")) {
    return { text: text.replace("BLOCK_ME", "<SECRET_1>"), findings: [finding("block")] };
  }
  const match = /SECRET_TOKEN_\d+/.exec(text);
  if (match) {
    const redacted = text.slice(0, match.index) + "<SECRET_1>" + text.slice(match.index + match[0].length);
    return { text: redacted, findings: [finding("redact")] };
  }
  if (text.includes("WARN_ME")) {
    return { text, findings: [finding("warn")] };
  }
  return { text, findings: [] };
}
