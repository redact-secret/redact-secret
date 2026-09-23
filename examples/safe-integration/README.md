# Safe browser and server integration

These executable JavaScript modules demonstrate the product boundary: browser
scanning is preventive UX, while the server scans every request again and is
the authoritative enforcement point.

The browser entry point, [`browser.mjs`](./browser.mjs), returns a request only
for clean or redacted text. A `warn` or `block` result contains safe finding
metadata but no request body, so UI code must resolve it before calling
`fetch`:

```js
import { prepareBrowserSubmission } from "./browser.mjs";

const submission = await prepareBrowserSubmission(userInput);
if (submission.state === "ready") {
  await fetch("/api/conversation", submission.request);
} else {
  showSecretNotice(submission.state, submission.findings);
}
```

The server entry point, [`server.mjs`](./server.mjs), applies an explicit
policy and refuses to call the downstream function for blocks, warnings,
scanner failures, invalid requests, or limit failures:

```js
import { createServerHandler } from "./server.mjs";

const handle = await createServerHandler({
  limits: {
    maxTransportBytes: 64 * 1024,
    maxInputBytes: 32 * 1024,
    maxOutputBytes: 32 * 1024,
    maxFindings: 32,
    maxConcurrentRequests: 8,
  },
  forward: ({ content }) => modelGateway.respond({ input: content }),
  record: ({ event, findingCount }) => auditSafeEvent({ event, findingCount }),
});

const result = await handle(requestBodyBytes);
```

`forward` receives only clean or redacted text. `record` receives event names,
limit names, and counts—never raw input, output, matched text, or an exception
message. Warning metadata is safe to render, but warning text remains
unredacted, so the example does not forward it. Transport bytes are bounded
before decoding; decoded input, sanitized output, finding count, and concurrent
requests are bounded before downstream use. `handle` never logs the raw
`bodyBytes` it receives, and reaches `JSON.parse` before any logging call
exists in this file—there is nothing here that could log a raw request body
ahead of scanning.

## Client and server policy differences

`prepareBrowserSubmission` calls `scanAndRedact(content)` with no `policy`
option, so it uses the library default. `createServerHandler` instead passes
the explicit `serverPolicy` declared in [`integration.mjs`](./integration.mjs).
The two happen to agree today—`serverPolicy` mirrors the default so that a
`ready` browser submission and an `OK` server response usually describe the
same decision, which keeps the UX predictable—but they are declared
independently. The server owns its policy outright: it can change thresholds,
add a stricter rule, or diverge from whatever the installed client bundle
does, without coordinating a client release, because the server always
recomputes its own decision from `request.content` rather than reading
anything the client sent about its own findings.

That independence is why the server never treats a client's decision as proof
of enforcement. The request body carries only `content`—never the client's
`findings`, `state`, or any other sanitized metadata—so `createServerHandler`
has nothing from the client it could trust even if it wanted to. A client
running stale code, a modified bundle, or no scanning at all changes nothing
about what the server does: it scans the bytes it actually received under its
own policy every time.

Findings from both entry points carry `start`/`end` offsets into the original
input the scan call was given—`content` for the browser, `request.content`
for the server—never into the sanitized `text`. A UI or log line that slices
the *sanitized* output with those offsets will read the wrong span; the
qualification harness (`scripts/consumer-harness.mjs`) asserts this by
slicing the original fixture with a returned finding's offsets and confirming
that substring never appears in the forwarded or submitted sanitized output.

The examples use the public `@redact-secret/core` API and do not implement a
detector. [`integration.test.mjs`](./integration.test.mjs) deterministically
tests the host control flow. The repository's installed-package qualification
copies these files into a clean consumer project and executes the success,
redact, block, warn, scan-failure, and limit paths against packed Node and
browser WebAssembly candidate artifacts. Its JSON evidence records the fixture
IDs and a `safeIntegration` result without recording fixture inputs.

Run the fast control-flow checks with:

```bash
npm run examples:test
```

Candidate-artifact qualification requires the built Node addon, browser
artifact, JavaScript package, and Playwright engine described by
[`scripts/qualify-package-consumer.mjs`](../../scripts/qualify-package-consumer.mjs).
It is executed by the repository's Artifact qualification workflow.
