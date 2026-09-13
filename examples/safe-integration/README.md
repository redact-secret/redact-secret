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
requests are bounded before downstream use.

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
