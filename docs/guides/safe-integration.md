# Policy and safe integration

[Documentation home](../README.md)

Scan untrusted text before logging, persistence, indexing, request forwarding,
or model/tool context construction. Browser scanning improves preventive UX;
the server must scan independently even when the client already did.

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

Whole-input APIs do not impose automatic input-size or finding-count limits.
Bound transport bytes before decoding, decoded input before scanning, and output,
concurrency, and memory before downstream use. A finding-count check performed
after scanning cannot prevent the allocation that already happened. Choose
limits appropriate to your application and test them with small synthetic inputs.

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
