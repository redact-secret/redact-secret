# Threat model

**Status:** current for `crates/secret-scan-core` and its bindings
(`@redact-secret/core` `0.1.0-beta.10`, `bindings/node`, `bindings/wasm`,
`bindings/python`, `crates/secret-scan-cli`) as described in
[`ARCHITECTURE.md`](../../ARCHITECTURE.md#security-boundaries) and
[`SECURITY.md`](../../SECURITY.md).

This document names the assets, attackers, data flow, trust boundary, and
residual risk for the deterministic scan-and-redact core. It complements
`ARCHITECTURE.md`'s security-boundaries section and `SECURITY.md`'s security
model; where they conflict, `SECURITY.md` governs. It is not one of the five
rule-bearing specs in `docs/specs/` (`detector-families.md`,
`contextual-detection.md`, `engine.md`, `distribution.md`,
`evidence-and-gates.md`); it does not state detection rules and carries no
per-row ADR citations. A control this document lists as a documented residual
risk, or as explicitly out of scope, is not a finding for `owasp-review` or
`vulnerability-test`.

## Assets

| Asset | Where it exists | Why it matters |
| --- | --- | --- |
| Original input text | Caller memory before `scan`/`scanAndRedact`; the core's scan buffer during detection | Contains every credential in the input, including ones no detector recognizes. The core cannot protect text the caller already holds. |
| Findings (classification + range) | The `findings` array returned by every scan API | Must describe what was found and where without ever including the matched plaintext. This is the one asset the product exists to produce safely. |
| Sanitized output text | The `text` result of `scanAndRedact` and the incremental sanitizer's emitted chunks | Placeholder text in place of matched ranges. `warn`/`allow` actions deliberately leave the original text unchanged in this output. |
| Findings supplied directly to `redact` | Caller-constructed input to the standalone `redact` API | Trusted caller assertions. The library validates metadata and ranges but does not verify they came from `scan` or that the chosen action matches server policy. |
| Custom detector, policy, and placeholder-formatter code | Loaded in-process by the caller, executed inside the scan/redact call | Trusted extensions. A detector receives plaintext candidates directly. |
| Incremental session state | Held across `push`/`flush` calls in the bounded incremental sanitizer | Retains a bounded tail of plaintext ("retained plaintext") while it decides whether a candidate is complete; never persisted, never emitted unredacted. |
| Build and publish artifacts | CI-built crates, N-API addons, wasm packages, Python wheels, the CLI binary | Consumers trust these to be built from reviewed source with a locked, `--ignore-scripts` dependency graph. |

## Attacker capabilities considered

1. **Untrusted input author.** Controls all bytes of the text handed to `scan`/`scanAndRedact`/the incremental sanitizer: token-like literals designed to false-positive or false-negative, adversarial Unicode (unpaired surrogates, confusables, zero-width and bidi control characters), oversized input, pathological repetition aimed at catastrophic-backtracking detector regexes, and many simultaneous candidates aimed at findings-count or allocation blowup.
2. **Untrusted model or tool output consumed downstream of redaction.** Cannot alter what the core already redacted, but can hand a careless caller a payload shaped to look like a valid finding if that caller forwards model output straight into `redact` instead of `scan`'s own findings — the "findings supplied directly to `redact` are trusted caller assertions" boundary in `SECURITY.md`.
3. **Malicious or careless custom detector, policy, or placeholder formatter.** In-process trusted code by design (`SECURITY.md` "Extension and caller trust"); can exfiltrate plaintext through its own return value, logs, or thrown errors if the caller loads an unreviewed extension.
4. **A caller that skips or misconfigures the authoritative server-side scan.** Client-side scanning is preventive UX, not enforcement (`ARCHITECTURE.md`); a caller that treats client-side redaction as sufficient exposes the server path.
5. **An unauthenticated or high-volume sender of scan requests at a server boundary.** Whole-input scanning has no built-in request-size, candidate-count, finding-count, output-size, or concurrency limit (`SECURITY.md` "Authoritative server limits"); the server, not the core, must enforce transport and decode limits.
6. **A supply-chain attacker targeting CI or a dependency.** Constrained by pinned action SHAs, `npm ci --ignore-scripts`, and reviewed install-script declarations (`SECURITY.md` "CI supply-chain review").
7. **Code already co-resident with the original input.** Out of scope for protection: anything that can read the caller's own process memory or variables before `scan` runs already holds the plaintext: the core cannot retroactively protect it.

## Data flow and trust boundary

```text
User / Tool / MCP / Log (untrusted text)
          |
          v
    Redact Secret (crates/secret-scan-core, via a binding)
          |
          v
     Sanitized text + findings (no plaintext)
          |
          v
Conversation / Context / Storage / Model
```

The trust boundary is the process running the core and its bindings.
Everything inside that boundary — the caller's own code, any custom
detector/policy/placeholder-formatter it loads, and the incremental session it
holds open — is trusted in-process code, not a distinct principal the core
defends against. A credential vault (a separate system) may contain secrets;
conversation history, model context, knowledge stores, logs, telemetry, and
diagnostics passing through this boundary must not (`ARCHITECTURE.md`).

Client-side scanning (browser `wasm-bindgen`, a client-side Node process) and
server-side scanning (an authoritative Node/Python/Rust/CLI service) share the
same core and the same guarantees; only their position relative to the network
edge differs. A client scan is preventive UX. A server scan run on the same or
untrusted text is the enforcement boundary and must run even when a client
also scanned (`ARCHITECTURE.md`).

## Protects against

- Matched plaintext appearing in findings, library errors, or diagnostics —
  findings and thrown errors carry classifications and original-input ranges
  only.
- Runtime network access, telemetry, secret storage, or environment-dependent
  behavior from the core itself — it is side-effect free by construction.
- A placeholder that could still contain a replaced matched range within its
  256-UTF-8-byte bound (rejected even for ranges shorter than four native
  range units).
- Determinism drift: the same input and configuration always produce the same
  findings and output, on every supported runtime, verified by the shared
  `conformance/` corpus.

## Does not protect against (documented, not findings)

| Limit | Why | Mitigation available to the caller |
| --- | --- | --- |
| Undetected credentials pass through as ordinary text | Detection is incomplete by design; the supported-family list is finite | Treat output as "known findings removed," never as "safe to send"; keep the supported family list current against `docs/support-matrix.md` |
| A findings-count/request-size/output-size/concurrency exhaustion at a server boundary | No built-in limit in whole-input scanning | Enforce transport-byte and decoded-input length limits before scanning; bound accepted findings and concurrent synchronous scans per measured latency/memory budgets |
| A caller forwarding untrusted model output straight into `redact` | Findings given directly to `redact` are trusted caller assertions, not re-verified against `scan` or server policy | Prefer `scan`'s own findings; never accept caller- or model-supplied `finding` objects from untrusted input |
| A malicious custom detector, policy, or placeholder formatter exfiltrating plaintext it legitimately receives | Extensions are in-process trusted code, not sandboxed | Use only reviewed extensions; never load one selected by untrusted request content |
| `warn`/`allow` findings leaving matched plaintext in the returned text | The action contract requires it | Default to `reject`/`redact` actions in policy; treat `passedThrough` counts as a signal, not a guarantee |
| Client-side-only enforcement | Client scanning is preventive UX, not the authoritative boundary | Always run the same core at the server boundary regardless of client behavior |
| Retained plaintext living in process memory for the duration of an incremental session's undecided tail | Managed runtimes copy and intern strings; the core cannot zeroize host-language memory | Configure the incremental sanitizer's bounded limits (total input, retained plaintext, token, multiline) to the narrowest values the workload tolerates; do not treat "bounded" as "erased" |
| A CI or dependency compromise that lands in a published artifact | Supply-chain review is a process control (pinned SHAs, `--ignore-scripts`, monthly review), not a runtime guarantee | Consumers verify published package integrity metadata; this repository reviews pinned actions and the lockfile at least monthly |

## Residual risks accepted

| Risk | Why accepted | Mitigation available to the caller |
| --- | --- | --- |
| A supported credential format changes shape upstream and the detector stops matching it | The core is deterministic against known formats, not a live validity oracle | Treat `docs/support-matrix.md` status as current-as-of, not permanent; report drift |
| A caller logs the raw request or tool body before scanning | Outside the core's control once the caller has the bytes | Never log raw bodies before the scan call; scan as early as possible in the pipeline |
| A caller treats a `warn`-action finding as already safe | `warn` and `allow` are opt-in policy choices that leave text unchanged | Default `reject`; require explicit opt-in and review before using `warn`/`allow` in a path that reaches storage or a model |
| An extension is reviewed once but later swapped for an unreviewed one via configuration | Extension identity is a caller-side configuration concern, not a core invariant | Pin extension source under the same review process as the application's own code |
| Findings-array size grows unbounded on adversarial input at a server without configured limits | The core does not impose a default | Server-side transport and candidate-count limits are a deployment requirement, not a library default |
