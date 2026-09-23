/**
 * Framework-neutral integration logic shared by the executable browser and
 * server examples. Detection is supplied by `@redact-secret/core`; this file
 * only enforces product policy and host resource limits.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const DEFAULT_SERVER_LIMITS = Object.freeze({
  maxTransportBytes: 64 * 1024,
  maxInputBytes: 32 * 1024,
  maxOutputBytes: 32 * 1024,
  maxFindings: 32,
  maxConcurrentRequests: 8,
});

// Declared independently of the browser side's default policy (browser.mjs
// calls `scanAndRedact` with no `policy` option). It happens to mirror that
// default today, but the server owns this declaration and can change it
// without any client release — see README.md#client-and-server-policy-differences.
export const serverPolicy = Object.freeze({
  evaluate(finding) {
    if (finding.type === "private_key") return "block";
    if (finding.confidence === "medium" || finding.confidence === "low") {
      return "warn";
    }
    return "redact";
  },
});

function safeFindings(findings) {
  return findings.map(
    ({ id, type, detector, confidence, action, start, end }) => ({
      id,
      type,
      detector,
      confidence,
      action,
      start,
      end,
    }),
  );
}

function checkedLimits(overrides = {}) {
  const limits = { ...DEFAULT_SERVER_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new TypeError(`${name} must be a positive safe integer`);
    }
  }
  return Object.freeze(limits);
}

function response(status, code, findings = []) {
  return Object.freeze({ status, code, findings: Object.freeze(safeFindings(findings)) });
}

/**
 * Preventive browser UX. A warning or block never produces a request body;
 * ready requests contain only the sanitizer's output. The server must scan it
 * again because this client-side decision is not authoritative.
 */
export function prepareBrowserSubmissionWith(scanAndRedact, content) {
  const result = scanAndRedact(content);
  const findings = safeFindings(result.findings);
  if (findings.some((finding) => finding.action === "block")) {
    return Object.freeze({ state: "blocked", findings: Object.freeze(findings) });
  }
  if (findings.some((finding) => finding.action === "warn")) {
    return Object.freeze({ state: "warning", findings: Object.freeze(findings) });
  }
  return Object.freeze({
    state: "ready",
    findings: Object.freeze(findings),
    request: Object.freeze({
      method: "POST",
      headers: Object.freeze({ "content-type": "application/json" }),
      body: JSON.stringify({ content: result.text }),
    }),
  });
}

/**
 * Authoritative server boundary. `forward` is reached only with scanned,
 * policy-approved text; `record` receives safe event metadata only.
 */
export function createServerHandlerWith({
  scanAndRedact,
  forward,
  record = () => {},
  limits: limitOverrides,
}) {
  if (typeof scanAndRedact !== "function" || typeof forward !== "function") {
    throw new TypeError("scanAndRedact and forward must be functions");
  }
  if (typeof record !== "function") throw new TypeError("record must be a function");

  const limits = checkedLimits(limitOverrides);
  let activeRequests = 0;

  return async function handle(bodyBytes) {
    if (!(bodyBytes instanceof Uint8Array)) {
      record({ event: "invalid_transport" });
      return response(400, "INVALID_TRANSPORT");
    }
    if (bodyBytes.byteLength > limits.maxTransportBytes) {
      record({ event: "limit_rejected", limit: "transport" });
      return response(413, "TRANSPORT_LIMIT_EXCEEDED");
    }
    if (activeRequests >= limits.maxConcurrentRequests) {
      record({ event: "limit_rejected", limit: "concurrency" });
      return response(503, "RESOURCE_LIMIT_EXCEEDED");
    }

    activeRequests += 1;
    try {
      let request;
      try {
        request = JSON.parse(decoder.decode(bodyBytes));
      } catch {
        record({ event: "invalid_transport" });
        return response(400, "INVALID_TRANSPORT");
      }

      if (
        typeof request !== "object" ||
        request === null ||
        Array.isArray(request) ||
        typeof request.content !== "string"
      ) {
        record({ event: "invalid_input" });
        return response(400, "INVALID_INPUT");
      }
      if (encoder.encode(request.content).byteLength > limits.maxInputBytes) {
        record({ event: "limit_rejected", limit: "input" });
        return response(413, "INPUT_LIMIT_EXCEEDED");
      }

      let result;
      try {
        result = scanAndRedact(request.content, { policy: serverPolicy });
      } catch {
        record({ event: "scan_failed" });
        return response(503, "SCAN_FAILED");
      }

      if (result.findings.length > limits.maxFindings) {
        record({ event: "limit_rejected", limit: "findings" });
        return response(422, "RESOURCE_LIMIT_EXCEEDED");
      }
      if (encoder.encode(result.text).byteLength > limits.maxOutputBytes) {
        record({ event: "limit_rejected", limit: "output" });
        return response(422, "OUTPUT_LIMIT_EXCEEDED");
      }
      if (result.findings.some((finding) => finding.action === "block")) {
        record({ event: "secret_blocked", findingCount: result.findings.length });
        return response(422, "SECRET_BLOCKED", result.findings);
      }
      if (result.findings.some((finding) => finding.action === "warn")) {
        record({ event: "secret_warning", findingCount: result.findings.length });
        return response(409, "SECRET_WARNING", result.findings);
      }

      try {
        await forward(Object.freeze({ content: result.text }));
      } catch {
        record({ event: "downstream_failed" });
        return response(502, "DOWNSTREAM_FAILED");
      }
      record({ event: "forwarded", findingCount: result.findings.length });
      return response(200, "OK", result.findings);
    } finally {
      activeRequests -= 1;
    }
  };
}
