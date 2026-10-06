# @redact-secret/core

Deterministic secret detection and redaction for runtime data and AI context,
for browser and server JavaScript/TypeScript applications.

Scan text in your process before it reaches logs, persistence, telemetry,
tool output, or model context. Detection is local and deterministic: no
network calls, no telemetry, and the same input always gives the same result.
Findings never include the matched secret. Browser scanning is preventive;
the server must scan again as the authoritative enforcement boundary (see
[safe integration](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/safe-integration.md)).

Redact Secret is not a DLP platform and does not detect every secret: it
finds supported credential formats and, only when you opt in, six bounded
structured PII families (at the Beta.11 qualification: five `provisional`, US SSN
`pending`, none `stable`),
and an empty finding list does not
prove text is secret-free. It complements repository and history scanners
rather than replacing them. Credential-family support is published in the
generated
[support matrix](https://github.com/redact-secret/redact-secret/blob/main/docs/support-matrix.md),
not stated by hand here; that matrix does not carry the PII families, whose statuses
are in the
[detection reference](https://github.com/redact-secret/redact-secret/blob/main/docs/reference/detection.md#opt-in-pii-availability-is-not-support).

One typed API, two artifacts: the package's `imports` map selects the Node
N-API addon on Node.js and the browser WebAssembly build everywhere else
(`decision-define-runtime-bindings`). Every built-in detector runs in the Rust
core, so both runtimes see the same findings for the same input.

## Install

```bash
npm install @redact-secret/core
```

Node.js 20, 22, and 24 are supported, on glibc and musl Linux, macOS, and
Windows (x64 and arm64). Where no addon can load — an unsupported platform, a
failed optional-dependency install, or an unloadable addon — `initialize()`
falls back to the WebAssembly artifact, and `artifact()` reports `"addon"` or
`"wasm"`. Cloudflare Workers is supported through the `workerd` export
condition; Vercel Edge is not. Browser applications need ES2022 and
WebAssembly support. The package is ESM only.

See the [JavaScript guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/javascript.md)
for browser asset loading and troubleshooting.

## Initialize once, then work synchronously

Every runtime requires one successful `await initialize()` before any
synchronous operation. On Node the underlying setup has nothing to await, but
the call stays part of the contract so the usage model does not vary by
runtime. It is idempotent, so any number of call sites may await it; a failed
attempt is not cached and may be retried.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

const { text, findings } = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_VALUE");

if (findings.some((finding) => finding.action === "block")) {
  throw new Error("Blocked sensitive input");
}

console.log(text);
```

Calling a synchronous operation first throws `SecretScanError` with code
`NOT_INITIALIZED`, without inspecting the input.

## Scan, redact, or both

```ts
import { initialize, redact, scan } from "@redact-secret/core";

await initialize();

const input = "API_KEY=SYNTHETIC_REVOKED_VALUE";
const findings = scan(input);
const redacted = redact(input, findings);
```

`scanAndRedact` does the same in one call, so the text and the findings cannot
disagree. `redact` expects the findings `scan` returned for that same input.
Each call is bounded by default to 64 MiB of input and 50,000 findings; pass
`limits: { maxInputBytes, maxFindings }` to change that. Exceeding a bound
fails with `INPUT_LIMIT_EXCEEDED` or `FINDING_LIMIT_EXCEEDED` rather than
truncating.

Every finding is frozen and carries only safe metadata — id, type, detector,
confidence, action, a range, and `obfuscation` (`"none"` or
`"invisible-characters"`). It never carries the matched value.

## Offsets are UTF-16 code units

`start` and `end` index the JavaScript string you passed in, so
`input.slice(start, end)` selects exactly the matched span. The exported
`RANGE_UNIT` states this, and the Rust core's UTF-8 byte offsets are converted
by each binding without changing the selected span.

```ts
import { initialize, RANGE_UNIT, scan } from "@redact-secret/core";

await initialize();

const input = "🔑 API_KEY=SYNTHETIC_REVOKED_VALUE";
const [finding] = scan(input);

if (finding !== undefined) {
  console.log(RANGE_UNIT, finding.start, finding.end);
  // Do not log input.slice(finding.start, finding.end): it is plaintext.
}
```

## Custom policy and placeholder formatter

The first stable extension surface is a policy and a placeholder formatter.
Both receive safe metadata only, never the input or a matched value. Custom
detector callbacks are not part of this API.

```ts
import {
  initialize,
  scanAndRedact,
  typedPlaceholderFormatter,
} from "@redact-secret/core";
import type { SecretPolicy } from "@redact-secret/core";

await initialize();

const policy: SecretPolicy = {
  evaluate: (finding) => (finding.confidence === "high" ? "block" : "warn"),
};

const result = scanAndRedact("api_key=SYNTHETIC_REVOKED_VALUE", {
  policy,
  placeholderFormatter: typedPlaceholderFormatter,
});
```

Omit `policy` to use the built-in policy, which runs in Rust. Pass
`defaultPlaceholderFormatter` to name the built-in placeholder format
(`<SECRET_1>`, `<SECRET_2>`, ...) explicitly; `typedPlaceholderFormatter`
names the finding type instead (`<JWT_1>`).

## Change one action without copying the default

A callback replaces the default action for every finding, so keeping the
default for the rest means reproducing it. `actionPolicy` is data instead: the
first rule that matches a finalized finding decides its action, and every
other finding keeps the default action the loaded artifact computes.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

const { text, findings } = scanAndRedact("ACME_AN_aB1cD2eF3gH4iJ5kL6mN", {
  ruleset: 'ruleset-revision: 1\ndetector: acme-alnum-token\nspecificity: contextual\nprefix: "ACME_AN_"\nalphabet: alnum\nrun: at-least 20\nvalidator: none\n',
  actionPolicy: {
    actionPolicyRevision: 1, // must be the first member
    base: "default",
    rules: [{ id: "redact-acme-tokens", match: { type: ["acme-alnum-token"] }, action: "redact" }],
  },
});
```

`actionPolicy` is accepted by `scan`, `scanAndRedact`, `createIncrementalSanitizer`
and the stream factories, as a plain object (serialized once, when the call or
session is created), as UTF-8 JSON text, or as bytes. The Rust core parses and
validates it; a rejected document throws `INVALID_ACTION_POLICY` (the code only
in 0.1.x) and a callback `policy` together with `actionPolicy` throws
`INVALID_OPTIONS`. An incremental session binds its policy when it is created.
`defaultPolicy` is the core's default evaluation as a policy object, for a
callback that wants "mine, else the default" without copying a table:

```ts
import { defaultPolicy } from "@redact-secret/core";
import type { SecretPolicy } from "@redact-secret/core";

const policy: SecretPolicy = {
  evaluate: (finding, context) => (finding.type === "acme-alnum-token" ? "redact" : defaultPolicy.evaluate(finding, context)),
};
```

The document format, evaluation order, limits and the rejection classes are in
the [action policy guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/action-policy.md).

## Explain and compare policies

`compareActionPolicies` answers "why did this finding get this action" and
"what changes if I swap policy A for policy B" without enforcing anything. It
runs detection **once**, then evaluates one to four policies (a baseline and up
to three candidates) on the same finalized findings:

```ts
import { compareActionPolicies, initialize } from "@redact-secret/core";

await initialize();

const comparison = compareActionPolicies("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", {
  policies: [
    { kind: "default" },
    {
      kind: "action-policy",
      actionPolicy: {
        actionPolicyRevision: 1,
        base: "default",
        rules: [{ id: "allow-github", match: { type: ["github_token"] }, action: "allow" }],
      },
    },
  ],
});

for (const finding of comparison.findings) {
  const [baseline, candidate] = finding.decisions;
  // baseline: redact, default-policy; candidate: allow, rule "allow-github" at index 0
  console.log(finding.type, baseline?.action, candidate?.action, candidate?.ruleId, finding.differs);
}
console.log(comparison.policies[1]?.documentSha256, comparison.changedCount);
```

A side is `{ kind: "default" }` (the default evaluation the loaded artifact
computes), `{ kind: "action-policy", actionPolicy }` (the same forms as the
`actionPolicy` option) or `{ kind: "callback", policy }` (a legacy
`SecretPolicy`). Each finding carries one decision per side, in order, with its
`action`, a `basis` (`rule`, `rule-default`, `no-rule-matched`,
`default-policy` or `callback`) and, for a rule, its `ruleId` and zero-based
`ruleIndex`. `differs` compares the actions only. `limits` and `ruleset` work as
for `scan`; PII is selected by `initialize`. The result is frozen plain data in
the CLI's `--json` shape, with `mode: "preview"` and `enforced: false`. It holds
no input byte, matched value or hash of either; the only digest is each action
policy side's `documentSha256`, the SHA-256 of the exact bytes the core parsed
(for an object, its compact `JSON.stringify` bytes). The default side evolves
with the artifact, so key evidence for it to `version` as well.

It covers finalized findings only (not overlap losers or anything detection
missed) and takes one string: there is no stream or incremental comparison, and
any option or side that could suggest one is `INVALID_OPTIONS`. A callback side
is called once per finding, in order, one side at a time, so a callback with
state advances it; if one throws the whole comparison fails with
`POLICY_FAILURE` (`INVALID_POLICY_ACTION` for a bad return) and returns nothing.
The scope, the bases and the cost are in the
[action policy guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/action-policy.md#explain-and-compare).

## Incremental and stream availability

The Node artifact builds a real incremental session, wrapping the same core
`IncrementalSanitizer` the Python binding does, and the browser (WebAssembly)
artifact builds the same kind of session over the compiled WebAssembly
module. `createIncrementalSanitizer` retains unresolved text until its
detection window closes, then emits sanitized text and findings;
concatenating every `append`/`finalize` result's text reconstructs the whole
sanitized output. Findings carry absolute UTF-16 offsets into the logical
whole-session input, so `input.slice(finding.start, finding.end)` selects the
matched span, on every runtime. Do not scan chunks independently — a
credential may cross a chunk boundary.

```ts
import { createIncrementalSanitizer, initialize } from "@redact-secret/core";

await initialize();

const limits = {
  maxInputBytes: 32_768,
  maxBufferedBytes: 16_512,
  maxTokenBytes: 8_192,
  maxMultilineBytes: 16_384,
};
const session = createIncrementalSanitizer({ limits });

const first = session.append("api_key=SYNTHETIC_REVOKED_");
const second = session.append("INCREMENTAL_VALUE\nordinary text");
const final = session.finalize();

const safeText = first.text + second.text + final.text;
```

The four limits are UTF-8 byte ceilings, enforced as such in the Rust core by
both artifacts. The older field names `maxInputCodeUnits`,
`maxBufferedCodeUnits`, `maxTokenCodeUnits` and `maxMultilineCodeUnits` are
deprecated aliases with the same meaning and keep working; naming both
spellings of one limit with different values throws `INVALID_LIMITS`. Findings
and their `start`/`end` ranges still use UTF-16 code units.

A session starts `accepting` and moves to the terminal `finalized` (one
successful `finalize()`), `aborted` (`abort()`), or `failed` (a limit,
detector, policy, or placeholder failure) state; every operation outside
`accepting` throws `INVALID_STATE`, and every terminal transition discards
whatever plaintext the session still retained.

`@redact-secret/core/node-stream` wraps a session in a byte-to-byte Node
`Transform`, finalizing it when the stream ends normally and aborting it on
every other exit:

```ts
import { pipeline } from "node:stream/promises";

import { initialize } from "@redact-secret/core";
import { createNodeStreamSanitizer } from "@redact-secret/core/node-stream";

await initialize();

await pipeline(
  process.stdin,
  createNodeStreamSanitizer({
    limits: {
      maxInputBytes: 32_768,
      maxBufferedBytes: 16_512,
      maxTokenBytes: 8_192,
      maxMultilineBytes: 16_384,
    },
  }),
  process.stdout,
);
```

`@redact-secret/core/web-stream` wraps a session in a byte-to-string Web
`TransformStream`, finalizing it when the writable side closes normally and
aborting it on every other exit:

```ts
import { initialize } from "@redact-secret/core";
import { createWebStreamSanitizer } from "@redact-secret/core/web-stream";

await initialize();

declare const source: ReadableStream<Uint8Array>;
declare const destination: WritableStream<string>;

await source
  .pipeThrough(
    createWebStreamSanitizer({
      limits: {
        maxInputBytes: 32_768,
        maxBufferedBytes: 16_512,
        maxTokenBytes: 8_192,
        maxMultilineBytes: 16_384,
      },
    }),
  )
  .pipeTo(destination);
```

See the [streaming guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/streaming.md).

## Errors

Every failure is a `SecretScanError` carrying nothing but a fixed `code` and
its fixed message — never the input, a matched value, a placeholder, or a
failing callback's own message.

```ts
import { initialize, scan, SecretScanError } from "@redact-secret/core";
import type { SecretScanErrorCode } from "@redact-secret/core";

try {
  await initialize();
  scan("API_KEY=SYNTHETIC_REVOKED_VALUE");
} catch (error) {
  if (error instanceof SecretScanError) {
    const code: SecretScanErrorCode = error.code;
    console.error(code);
  }
}
```

`NOT_INITIALIZED` and `INITIALIZATION_FAILED` come from the binding layer,
`INVALID_CHUNK` and `INVALID_UTF8` from the stream adapters,
`UNPAIRED_SURROGATE` from this package's own input check — a JavaScript
string may contain a lone UTF-16 surrogate, which has no UTF-8
representation, so `scan`, `redact`, `scanAndRedact`, and an incremental
sanitizer's `append` all reject one with this fixed code before it reaches
either binding, identically on Node.js and in the browser. Core failures are
mapped to the same fixed error vocabulary.

## Public API

Runtime values: `initialize`, `artifact`, `scan`, `redact`, `scanAndRedact`,
`compareActionPolicies`, `piiActivation`, `status`, `createIncrementalSanitizer`, `defaultPlaceholderFormatter`,
`defaultPolicy`, `typedPlaceholderFormatter`, `SecretScanError`, `RANGE_UNIT`,
`VERSION`, `PROFILE`.

Types: `InitializeOptions`, `CoreStatus`, `ArtifactKind`, `DetectedSecretFinding`, `SecretFinding`, `SecretAction`,
`SecretConfidence`, `SecretObfuscation`, `SecretPolicy`, `PolicyContext`, `PlaceholderFormatter`,
`PlaceholderContext`, `ScanOptions`, `RedactOptions`, `ScanAndRedactOptions`,
`ScanResult`, `WholeInputLimits`, `IncrementalSanitizer`, `IncrementalSanitizerOptions`,
`IncrementalSanitizerResult`, `IncrementalSanitizerState`,
`IncrementalLimits`, `IncrementalSecretPolicy`, `IncrementalPolicyContext`,
`ActionPolicyDocument`, `ActionPolicyInput`, `ActionPolicyRule`,
`ActionPolicyMatch`, `ActionPolicyRuleAction`, `DefaultSecretPolicy`,
`CompareActionPoliciesOptions`, `ComparedPolicy`, `ComparedPolicyKind`,
`ActionComparison`, `ComparedPolicySummary`, `ComparisonDetection`,
`ComparedFinding`, `ActionDecision`, `ActionCounts`, `DecisionBasis`,
`RangeUnit`, `SecretScanErrorCode`.

PII activation is opt-in and off by default. Pass `pii` selectors to
`initialize`, for example `await initialize({ pii: ["pii"] })`, then read the
canonical identity with `piiActivation()`. It covers six bounded structured
families (email, IBAN, network address, payment card, phone, US SSN); at the
Beta.11 `pii-v1` qualification the first five are `provisional` and US SSN is
`pending`, none `stable`. Availability is not a support claim. The `pii`
selection is an `initialize` option, not a separate subpath import. A browser
or Worker fetches the PII WebAssembly build only when the first `initialize`
call selects PII. See the
[JavaScript guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/javascript.md).

Stream subpaths: `@redact-secret/core/node-stream` exports
`createNodeStreamSanitizer`, `NodeStreamSanitizer`, and `SecretScanError`;
`@redact-secret/core/web-stream` exports `createWebStreamSanitizer`,
`WebStreamSanitizer`, and `SecretScanError`. `@redact-secret/core/common/node-stream`
and `@redact-secret/core/common/web-stream` export the same names, bound to
the `common` runtime instead of `full` (see below).

`@redact-secret/core/common` exports the same runtime values and types as the
root, backed by the opt-in `common` detector profile: `PROFILE` is `"common"`
there and `"full"` on the root. `common` omits every provider detector, so a
bare provider token is not detected. `initialize()` rejects with
`INITIALIZATION_FAILED` when the loaded artifact reports a different profile
than the entry point that loaded it. `@redact-secret/core/node-stream` and
`@redact-secret/core/web-stream`'s `createNodeStreamSanitizer` and
`createWebStreamSanitizer` factories always open a `full` session; for a
`common` byte stream, use `createNodeStreamSanitizer`/`createWebStreamSanitizer`
from `@redact-secret/core/common/node-stream`/`@redact-secret/core/common/web-stream`
instead — a browser bundle resolving one of those two subpaths never resolves
the `full` runtime or the root `@redact-secret/wasm` artifact. The
`NodeStreamSanitizer`/`WebStreamSanitizer` classes themselves are
profile-agnostic and identical across all four subpaths, so constructing one
directly with a session from `@redact-secret/core/common`'s
`createIncrementalSanitizer` still works too.

The root export, `@redact-secret/core/common`, and the four stream subpaths
are the executable public API.
`@redact-secret/core/package.json` also exposes package metadata. Internal
modules are unreachable through the `exports` map. `VERSION` is
the shared product version; the Rust crate, this package, the Python package,
and the CLI are released in lockstep
(`decision-release-bindings-in-lockstep`), and `initialize()` refuses an
artifact that reports a different one.

## Security

Client-side scanning is preventive UX; server-side scanning is the
authoritative enforcement boundary. See
[SECURITY.md](https://github.com/redact-secret/redact-secret/blob/main/SECURITY.md)
for the security model and private vulnerability reporting.

## License

[MIT](https://github.com/redact-secret/redact-secret/blob/main/LICENSE)
