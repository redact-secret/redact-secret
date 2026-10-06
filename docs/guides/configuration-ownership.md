# Configuration ownership

[Documentation home](../README.md) · [Capability matrix](../reference/detector-capability-matrix.md) · [Action policy](action-policy.md)

Who owns each kind of configuration on each surface, and how to keep several
independent configurations in one deployment. The decision behind this page is
[`decision-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python`](../decisions/2026-10-06-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python.md)
([#1222](https://github.com/redact-secret/redact-secret/issues/1222)): no new
configuration-bound scanner handle is added for Node, WebAssembly or Python in
0.1.x. This page is the supported alternative, and the
[evidence](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1222/README.md) records that every example below
was run.

## Three kinds of configuration

| Kind | What it is | Where it acts |
| --- | --- | --- |
| Detection configuration | the profile (`full` or `common`), the PII selection, and an optional ruleset | before findings exist: decides what can be found |
| Action policy | a declarative [action policy](action-policy.md) document or a legacy callback | after findings are final: decides `redact`, `block`, `warn` or `allow` per finding |
| Host limits | whole-input limits, incremental limits, the formatter | around the call: bounds work and shapes output |

An action policy cannot recover a candidate that detection did not emit, and it
is not a sensitivity control. A PII selection is an activation, not a
threshold. No surface offers per-detector selection or a numeric sensitivity.

## Who owns what, per surface

| Surface | Detection configuration | Action policy | Host limits |
| --- | --- | --- | --- |
| Rust | each registry value: `BuiltInRegistry` (`Send + Sync`, built-ins and PII) or `DetectorRegistry` (`!Send`, adds a ruleset and custom detectors); no global state | an argument of each call, or of each compared side | an argument (`WholeInputLimits`, `IncrementalLimits`) |
| Node (`@redact-secret/core`) | one runtime per entry point per thread: the profile is the import (`@redact-secret/core` is `full`, `/common` is `common`), PII is the first `initialize({ pii })`, a ruleset is a per-call option | the `actionPolicy` option of each call, or `compareActionPolicies` sides | per-call `limits` |
| WebAssembly (browser, workerd, Node fallback) | one runtime per entry point per module instance; the artifact is chosen at load (`full` or `common`, with or without `pii`) | the same options as Node | the same options as Node |
| Python | one process: the first `initialize(pii=...)` holds for every thread; a ruleset is a per-call argument; the wheel is `full` only | `action_policy=` of each call, or `compare_action_policies` sides | per-call `limits` |
| CLI | one invocation: `--pii`, `--ruleset`; `full` only | `--action-policy`, `--compare-action-policy` | fixed by the binary |

In every binding the Rust core is stateless: the sharing described below lives
in the binding's own ownership layer, not in detection.

## Recipes

### Rust: one registry per configuration, shared across threads

A `BuiltInRegistry` is immutable and `Send + Sync`, carries its own PII
selection, and runs the same pipeline as the free functions. Build one per
configuration at startup and clone the `Arc`. Three configurations coexist with
no cross-talk, in any construction order, and in the same process.

```rust
use std::sync::Arc;
use std::thread;

use redact_secret::{BuiltInRegistry, DefaultPolicy, PiiSelection};

const TEXT: &str = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n";

// One immutable registry per configuration, built once and shared.
let off = Arc::new(BuiltInRegistry::with_built_in()?);
let global = Arc::new(BuiltInRegistry::with_built_in_and_pii(
    &PiiSelection::parse(&["pii:global"])?,
)?);
let network = Arc::new(BuiltInRegistry::with_built_in_and_pii(
    &PiiSelection::parse(&["pii:family:global:network-address"])?,
)?);

let counts: Vec<usize> = thread::scope(|scope| {
    [&off, &global, &network]
        .map(|registry| {
            let registry = Arc::clone(registry);
            scope.spawn(move || registry.scan(TEXT, &DefaultPolicy).unwrap().len())
        })
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect()
});
assert_eq!(counts, [0, 2, 1]);
```

(The block is the body of a function returning `Result`; the repository test
runs it.) A registry that needs a ruleset is a `DetectorRegistry`: it is
`!Send`, so build one per thread. An `IncrementalSanitizer` builds its own
registry per session and carries its own PII selection, so sessions with
different selections can be interleaved.

### Any surface: the action policy belongs to the call

A policy is an argument, so a different policy never needs a different scanner,
and the registry or runtime holds none. Rust:

```rust
use redact_secret::{
    BuiltInRegistry, ComparedPolicy, default_placeholder_formatter, load_action_policy,
};

let registry = BuiltInRegistry::with_built_in()?;
let text = format!("API_KEY={}{}{}", "ghp", "_SYNTHETICREVOKED", "0".repeat(20));
let keep_github = load_action_policy(
    br#"{"actionPolicyRevision":1,"base":"default","rules":[
        {"id":"keep-github","match":{"type":["github_token"]},"action":"warn"}]}"#,
)?;

// The policy is handed to the call; the registry holds no policy.
let enforced = registry.scan_and_redact(&text, &keep_github, &default_placeholder_formatter)?;
assert_eq!(enforced.text(), text);

// Previewing a policy change runs detection once, under the same registry.
let comparison = registry.compare_action_policies(
    &text,
    &[
        ComparedPolicy::Default,
        ComparedPolicy::ActionPolicy(&keep_github),
    ],
)?;
assert_eq!(comparison.changed_count(), 1);
```

Node and WebAssembly (`actionPolicy`, `compareActionPolicies`):

```js
import { compareActionPolicies, initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

// The action policy is an argument of each call. Nothing is configured once,
// and a second policy in the same thread never affects the first.
const TEXT = "API_KEY=" + ["ghp", "_SYNTHETICREVOKED", "0".repeat(20)].join("");
const keepGithub = {
  actionPolicyRevision: 1,
  base: "default",
  rules: [{ id: "keep-github", match: { type: ["github_token"] }, action: "warn" }],
};

console.log("default:", scanAndRedact(TEXT).text === TEXT ? "unchanged" : "redacted");
console.log("keep-github:", scanAndRedact(TEXT, { actionPolicy: keepGithub }).text === TEXT ? "unchanged" : "redacted");

// A policy change is previewed over one detection pass before it is adopted.
const comparison = compareActionPolicies(TEXT, {
  policies: [{ kind: "default" }, { kind: "action-policy", actionPolicy: keepGithub }],
});
const [finding] = comparison.findings;
console.log(finding.decisions.map((decision) => decision.action).join(" -> "), "changed:", comparison.changedCount);
```

```text
default: redacted
keep-github: unchanged
redact -> warn changed: 1
```

Python (`action_policy=`, `compare_action_policies`):

```python
import redact_secret
from redact_secret import ComparedPolicy

redact_secret.initialize()

# The action policy is an argument of each call, so any number of policies can
# be used in one process and one thread without sharing state.
TEXT = "API_KEY=" + "".join(["ghp", "_SYNTHETICREVOKED", "0" * 20])
KEEP_GITHUB = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "keep-github", "match": {"type": ["github_token"]}, "action": "warn"}],
}

print("default:", "unchanged" if redact_secret.scan_and_redact(TEXT).text == TEXT else "redacted")
kept = redact_secret.scan_and_redact(TEXT, action_policy=KEEP_GITHUB)
print("keep-github:", "unchanged" if kept.text == TEXT else "redacted")

# A policy change is previewed over one detection pass before it is adopted.
comparison = redact_secret.compare_action_policies(
    TEXT, [ComparedPolicy.default(), ComparedPolicy.action_policy(KEEP_GITHUB)]
)
finding = comparison.findings[0]
print(" -> ".join(str(decision.action) for decision in finding.decisions), "changed:", comparison.changed_count)
```

```text
default: redacted
keep-github: unchanged
redact -> warn changed: 1
```

The comparison is a preview over finalized findings and enforces nothing; see
[explain and compare](action-policy.md#explain-and-compare).

### Node: one Worker per PII configuration

A Node thread has one runtime per entry point, so independent PII selections
need independent threads. A `worker_threads` Worker evaluates its own copy of
the package, so it is a separate owner; the main thread is one more. Call
`initialize` once in each Worker, before its first scan.

```js
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";

const TEXT = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n";
const TENANTS = {
  "pii-off": undefined,
  "pii-global": ["pii:global"],
  "network-address-only": ["pii:family:global:network-address"],
};

if (isMainThread) {
  // One Worker per tenant. Each Worker evaluates its own copy of the package,
  // so the one initialize() it makes is the only configuration that copy sees.
  const scanInWorker = (tenant) =>
    new Promise((resolve, reject) => {
      const worker = new Worker(new URL(import.meta.url), { workerData: { tenant } });
      worker.once("message", resolve);
      worker.once("error", reject);
    });
  const results = await Promise.all(Object.keys(TENANTS).map(scanInWorker));
  for (const { tenant, types } of results) console.log(tenant, JSON.stringify(types));
} else {
  const { initialize, scan } = await import("@redact-secret/core");
  const pii = TENANTS[workerData.tenant];
  await initialize(pii === undefined ? {} : { pii });
  const types = scan(TEXT)
    .map((finding) => finding.type)
    .sort();
  parentPort.postMessage({ tenant: workerData.tenant, types });
}
```

```text
pii-off []
pii-global ["pii_global_email","pii_global_network_address"]
network-address-only ["pii_global_network_address"]
```

Costs and limits: the boundary is asynchronous message passing, so a logging or
tracing adapter that must scan synchronously on the calling thread cannot use
it; a Worker is single-threaded and its sessions must not cross Workers; and
each Worker holds its own runtime. Terminating a Worker leaves the others
unchanged.

### WebAssembly: one module instance per configuration

A WebAssembly module instance owns its memory and state. Instantiating the
generated glue once per configuration gives independent owners in one thread.
`@redact-secret/core` does not expose this: it binds one instance per entry
point, so the recipe uses the glue that `node scripts/build-browser-artifact.mjs`
writes. The `pii` artifact is a separate file: a tenant that needs PII must
load it, and a PII-off tenant can load the smaller default one. A distinct
module URL gives a distinct instance on Node; a bundler that merges equal URLs
defeats the technique, so confirm it on your bundler.

```js
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Usage: node wasm-instance-tenants.mjs <artifact directory>
// The directory is the output of `node scripts/build-browser-artifact.mjs`.
const dir = process.argv[2];
const TEXT = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n";
const TENANTS = {
  "pii-off": { stem: "redact_secret_wasm", pii: [] },
  "pii-global": { stem: "redact_secret_wasm_pii", pii: ["pii:global"] },
  "network-address-only": { stem: "redact_secret_wasm_pii", pii: ["pii:family:global:network-address"] },
};

// A module instance owns its state. Evaluating the generated glue under a
// distinct URL gives one instance per tenant. The facade binds one instance per
// entry point and does not do this, and a bundler may merge equal module URLs.
async function instanceFor(tenant, { stem, pii }) {
  const glue = await import(`${pathToFileURL(join(dir, `${stem}.js`)).href}?instance=${tenant}`);
  glue.initSync({ module: readFileSync(join(dir, `${stem}_bg.wasm`)) });
  glue.initialize(pii);
  return glue;
}

const instances = {};
for (const [tenant, config] of Object.entries(TENANTS)) instances[tenant] = await instanceFor(tenant, config);
for (const [tenant, glue] of Object.entries(instances)) {
  console.log(
    tenant,
    JSON.stringify(
      glue
        .scan(TEXT)
        .map((finding) => finding.type)
        .sort(),
    ),
  );
}
```

```text
pii-off []
pii-global ["pii_global_email","pii_global_network_address"]
network-address-only ["pii_global_network_address"]
```

Each initialized `pii` instance held about 1.7 MiB of resident memory in one
indicative run; that is a footprint fact, not a performance claim.
Artifact sizes are in the [matrix](../reference/detector-capability-matrix.md#5-webassembly-artifact-footprint).

### Python: one process per PII configuration

The wheel keeps the PII selection in one process-wide static, so one process
holds one selection, whichever thread asks, and `import redact_secret` fails
inside a Python 3.14 sub-interpreter. Give each configuration its own process.
A single-worker `ProcessPoolExecutor` per tenant with the `spawn` start method
gives each a fresh interpreter, and the pool initializer is the one place its
selection is set.

```python
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import redact_secret

TEXT = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n"
TENANTS = {
    "pii-off": (),
    "pii-global": ("pii:global",),
    "network-address-only": ("pii:family:global:network-address",),
}


def configure(pii):
    # Runs once in the tenant's own process, the only place its selection lives.
    redact_secret.initialize(pii=pii)


def scan_types():
    return sorted(finding.type for finding in redact_secret.scan(TEXT))


def main():
    # One single-process pool per tenant. "spawn" gives every worker a fresh
    # interpreter, so no selection is inherited from this process.
    context = multiprocessing.get_context("spawn")
    for tenant, pii in TENANTS.items():
        with ProcessPoolExecutor(1, mp_context=context, initializer=configure, initargs=(pii,)) as pool:
            print(tenant, pool.submit(scan_types).result())

    # Inside one process the first selection wins and a different one conflicts.
    redact_secret.initialize(pii=("pii:global",))
    try:
        redact_secret.initialize(pii=("pii:family:global:network-address",))
    except redact_secret.PiiActivationConflictError as error:
        print(error.code)


if __name__ == "__main__":
    main()
```

```text
pii-off []
pii-global ['pii_global_email', 'pii_global_network_address']
network-address-only ['pii_global_network_address']
PII_ACTIVATION_CONFLICT
```

There is no thread-shareable Python handle: all threads of a process share its
one selection. Use a process pool per configuration, or run the Rust
`BuiltInRegistry` where you need a registry shared across threads.

### CLI: one invocation per configuration

Every run is independent. `--pii`, `--ruleset` and `--action-policy` apply to
that run only, and a finding makes the exit status 1.

```sh
redact-secret tenant.txt
redact-secret --pii pii:global tenant.txt
redact-secret --pii pii:family:global:network-address tenant.txt
```

With `tenant.txt` holding the two synthetic lines of the examples above, the
runs print, in order:

```text
redact-secret: 0 finding(s) in 1 source(s); ranges are utf8-bytes
tenant.txt:7-41 pii_global_email detector=pii-domain confidence=high action=redact obfuscation=none id=finding-1
tenant.txt:54-65 pii_global_network_address detector=pii-domain confidence=high action=redact obfuscation=none id=finding-2
redact-secret: 2 finding(s) in 1 source(s); ranges are utf8-bytes
tenant.txt:54-65 pii_global_network_address detector=pii-domain confidence=high action=redact obfuscation=none id=finding-1
redact-secret: 1 finding(s) in 1 source(s); ranges are utf8-bytes
```

## Why a second JavaScript wrapper does not isolate the singleton

Wrapping `@redact-secret/core` in your own object, or configuring it from a
second module, does not create a second owner. All of them call the same
runtime for the entry point, and the first PII selection in a thread holds. An
equivalent selection is idempotent and a differing one is
`PII_ACTIVATION_CONFLICT`, so one component's `initialize` can turn another's
into an error:

```js
import { initialize, piiActivation } from "@redact-secret/core";

// Within one thread there is one runtime per entry point. A second selection
// does not create a second owner; it conflicts with the first.
await initialize({ pii: ["pii:global"] });
await initialize({ pii: ["pii", "pii:global"] }); // equivalent selection: idempotent
try {
  await initialize({ pii: ["pii:family:global:network-address"] });
} catch (error) {
  console.log(error.code);
}
console.log(piiActivation().includes("selectors=pii:global;"));
```

```text
PII_ACTIVATION_CONFLICT
true
```

A conflict leaves the active selection unchanged. An adapter that passes no
`pii` option accepts the application's selection, and one that passes `pii`
verifies it; keep that ordering. Check what is active with `status()` and
`piiActivation()` instead of initializing to find out.

## Not supported

- A second PII selection, profile or ruleset in one thread (Node), one module
  instance (WebAssembly) or one process (Python), and reconfiguring after
  initialization.
- A configuration-bound scanner object in Node, WebAssembly or Python, and a
  `Sanitizer` builder that bundles detection, policy and formatter.
- Sharing a configuration between Workers or processes; each owns its own.
- A thread-shareable Python handle.
- Selecting individual detectors by id, a numeric sensitivity or confidence
  threshold, and choosing `common` or `full` implicitly from a PII selection.
- Comparing policies inside an incremental session or stream.
- Treating an action policy as a way to detect more. It only acts on findings
  that exist.

## When to ask for more

The decision lists the evidence that would reopen it: a stated in-process
multi-tenant PII requirement with evidence that Workers, instances or processes
cannot serve, an adapter that cannot work without a handle
([adapters#213](https://github.com/redact-secret/redact-secret-adapters/issues/213)),
or a measured construction cost that matters. See the
[decision](../decisions/2026-10-06-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python.md#6-reopen-triggers).
