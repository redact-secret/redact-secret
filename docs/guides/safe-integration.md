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

## Extension trust

Policy and formatter callbacks receive safe metadata, not plaintext. They are
trusted application code, not a sandbox: a closure can still capture raw input.
Placeholders must be non-empty, at most 256 UTF-8 bytes, and cannot reproduce an
eligible replaced matched value. Keep them short and unrelated to input.

`redact` validates ranges but does not authenticate findings or rerun detection.
Use findings from the same original input. Detection can miss unsupported formats;
see [detection limits](../reference/detection.md). For a security report, follow
[SECURITY.md](../../SECURITY.md) using synthetic or revoked examples only.
