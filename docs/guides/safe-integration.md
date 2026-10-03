# Policy and safe integration

[Documentation home](../README.md)

Scan untrusted text before logging, persistence, indexing, request forwarding,
or model/tool context construction. Browser scanning improves preventive UX;
the server must scan independently even when the client already did.

## Where the authoritative scan belongs

A client can be modified, skipped, or replaced, so a scan that runs on the
user's device is preventive UX: it keeps a pasted credential from leaving the
device in the ordinary case. The server scans again, independently, before
logging, storage, context construction, and model or tool invocation, and that
scan is the one your security decisions rely on. Use the default `full`
detector profile for it. The smaller opt-in `common` profile is for preventive
consumers such as a browser or a small agent process; it drops provider-specific
detectors by design, so it is never the authoritative boundary
([detector profiles](../reference/detection.md#detector-profiles)).

## Actions are decisions your host consumes

| Action | Library output | Host responsibility |
| --- | --- | --- |
| `redact` | Replaces the range | Use returned text |
| `block` | Replaces the range | Reject the operation if blocking is required |
| `warn` | Preserves the range | Decide whether warning-only is acceptable |
| `allow` | Preserves the range | Accept that this detected text remains |

The default policy blocks private-key material, redacts recognized credentials
and other high-confidence findings, and warns on other medium/low-confidence
findings. A stricter policy can redact or block every **detected** finding;
it does not expand detector coverage.

This server helper rejects blocked results and propagates sanitized library
errors. Its caller must initialize the runtime and enforce request limits first:

```ts
import { scanAndRedact } from "@redact-secret/core";

export function sanitizeForStorage(input: string): string {
  const result = scanAndRedact(input);
  if (result.findings.some((finding) => finding.action === "block")) {
    throw new Error("Blocked sensitive input");
  }
  return result.text;
}
```

If initialization or processing fails, stop the operation. Returning raw input
from a catch block defeats the boundary. Never log raw callback exceptions,
input excerpts, request bodies, or `input.slice(start, end)`.

For a runnable browser/server pair, see the
[safe integration examples](../../examples/safe-integration/README.md). They
exercise clean, redact, block, warn, failure, and limit paths, and the artifact
qualification workflow runs them against clean installs of the packed Node and
browser WebAssembly candidates.

## Bound resources before scanning

Whole-input `scan`, `redact`, and `scanAndRedact` are bounded by default: 64 MiB
of input and 50,000 findings, failing closed with `INPUT_LIMIT_EXCEEDED` or
`FINDING_LIMIT_EXCEEDED` rather than returning a truncated result
(`decision-bound-whole-input-operations-by-default`; pass `limits` to raise or
lower them). Those defaults are a ceiling, not a request budget. By the time
the check runs, your process already holds the decoded string, so bound
transport bytes before decoding, decoded input before scanning, and output,
concurrency, and memory before downstream use. Choose limits appropriate to
your application and test them with small synthetic inputs. A failed scan must
stop the operation: never fall back to the raw input.

Incremental APIs require explicit limits but may emit a prefix before a later
failure. Stage output until successful finalization when a downstream operation
must be atomic. Do not independently scan chunks.

## Completeness, limits and deadlines

The contract behind this section is in
[Completeness of `Ok`](../reference/api-contract.md#completeness-of-ok) and
[Cancellation and time bounds](../reference/api-contract.md#cancellation-and-time-bounds).

- **Fail closed on any error.** A whole-input call that returns a value has
  inspected the whole input with every detector of the registry you selected.
  Any error, whatever its code, means no result exists: no findings and no
  redacted text come with it. Reject, drop or quarantine the input. Treat an
  unknown error code as a failure too, because the set of codes grows.
- **Treat only a returned value as completeness.** Do not infer it from an
  empty findings list, from a timeout, from a log line, or from a client that
  says it already scanned. A value is complete inspection, not proof that
  nothing sensitive remains: `warn` and `allow` findings stay in the text, and
  a format no detector covers is not found.
- **Do not retry with partial output.** Never fall back to the raw input, to a
  truncated input, to a `common` profile run after a `full` run failed, or to
  findings gathered before the failure. A retry that you accept must run the
  same scan over the same whole input and be judged by the same rule.
- **Do not reuse an incremental prefix as a result.** An incremental session, a
  stream adapter and the CLI on standard input can release sanitized text
  before a later failure. Stage that output and publish it only after
  `finalize` succeeds (or the CLI exits `0`).
- **Size limits to the capacity you will hold.** Version 0.1.x has no
  cancellation, deadline or work budget, so a started scan holds its CPU and
  memory (the input, a normalized copy, the candidates and the output) until
  it really returns. The 64 MiB and 50,000-finding defaults are a ceiling, not
  a plan. Set `max_input_bytes` and `max_findings` from the CPU time and
  memory you are willing to spend per request, and measure that on your own
  hardware with your own profile, PII selection and rulesets. The repository
  publishes no per-byte cost bound; its adversarial runtime caps are
  test-only.
- **Run where you can terminate the worker if you need a hard deadline.** Put
  the scan on a thread, child process or JavaScript worker that you can
  terminate, bound the number of scans in flight, and discard everything the
  worker produced when you terminate it. Timing out an `await`, dropping a
  future or abandoning a promise leaves the scan running and holding its
  resources. In Python a thread cannot be killed; use a child process for a
  hard deadline.
- **Do not scan on a latency-critical thread.** A call blocks its caller for
  as long as it runs, including a JavaScript event loop or an async reactor.
  Move large inputs to a separate worker.

Policy and formatter callbacks receive safe metadata, not plaintext. They are
trusted application code, not a sandbox: a closure can still capture raw input.
Placeholders must be non-empty, at most 256 UTF-8 bytes, and cannot reproduce an
eligible replaced matched value. Keep them short and unrelated to input.

`redact` validates ranges but does not authenticate findings or rerun detection.
Use findings from the same original input. Detection can miss unsupported formats;
see [detection limits](../reference/detection.md). For a security report, follow
[SECURITY.md](../../SECURITY.md) using synthetic or revoked examples only.
