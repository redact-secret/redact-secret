# Custom composition: build an artifact with only the detectors you choose

A **custom composition** is a WebAssembly artifact built for one application
from a declarative `composition/v1` file. It links only the built-in detectors
the file selects. It is a build-time choice made in your build tooling; nothing
in the core runtime reads a file, runs your code or fetches another artifact.

It is **not a profile**. The profiles stay `full` and `common`; a custom
artifact reports `PROFILE === "custom"` and a composition identity, and the
published `@redact-secret/core` entries never load one
([`decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`](../decisions/2026-10-07-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support.md)).

Status: **current** for WebAssembly and for Rust composed natively;
**unsupported** for a custom Node addon, Python wheel or CLI (see
[Targets](#targets)).

## What you get, and what you do not

Removing a detector removes that detector's code, grammar tables, finding-type
names and prefilter literals from the binary. It removes **nothing else**: the
pipeline, overlap resolution, redaction, the action-policy engine, the
incremental sanitizer and the retention hints it consults for every built-in
id, the ruleset adapter, the configuration resolver and the dependency code all
stay (`ENGINE_FLOOR` in `scripts/build-custom-artifact.mjs` lists them, and
`capability-report.json` repeats the list). **No size or speed guarantee
follows from selecting fewer detectors.** Measure your own artifact against a
`full` baseline (see [Evidence](#evidence)); the retained engine floor is large,
so a saving is smaller than the number of removed detectors suggests.

A selection can lose coverage: overlap resolution is global, so a span a
removed detector would have owned can be reported by a weaker included detector
(`generic-token`, `bearer-token`) with that detector's type and default action,
or not at all. A server that enforces policy should keep scanning with an
unselected `full` artifact; client-side scanning is preventive UX.

## The input

```json
{
  "schema": "composition/v1",
  "name": "edge-checks",
  "include": ["github-token", "jwt", "generic-token"],
  "pii": "none"
}
```

| Member | Rule |
| --- | --- |
| `schema` | `"composition/v1"` |
| `name` | a lowercase identifier of at most 64 bytes; it is part of the identity |
| `include` | 1 to 256 built-in detector ids; order as written is ignored, the canonical registration order is used; aliases resolve, repeats and unknown ids fail |
| `pii` | `"none"` or `"all"`: whether the PII runtime is linked (never selected per family at build time; the PII selector still chooses families at `initialize()`) |

No other member exists: no ruleset, policy or limit. An unknown schema or
member is rejected. Every failure names a fixed code and a fixed-syntax path
(`include[3]`); an unknown or malformed string is never echoed, because a
secret can be pasted where an id belongs.

The **composition identity** is `custom:` and the SHA-256 (lowercase hex) of the
canonical document `{"include":[<canonical ids>],"name":"<name>","pii":"none"|"all","schema":"composition/v1"}`
(members in bytewise order, no whitespace). Rust `Composition::new` and
`scripts/lib/composition.mjs` derive the same value, pinned by
[`conformance/fixtures/composition-v1.json`](../../conformance/fixtures/composition-v1.json),
and the build fails if the built artifact's manifest says otherwise.

## Building

```sh
npm run js:build   # the wrapper reuses the package's runtime
npm run wasm:build:custom -- --config redact.composition.json --out-dir src/vendor/redact
```

| Option | Meaning |
| --- | --- |
| `--config <file>` | the `composition/v1` JSON file (required) |
| `--out-dir <dir>` | where the artifact is emitted; default `target/custom-artifacts/<name>` |
| `--work-dir <dir>` | the isolated build workspace; default `<out-dir>.work` |
| `--baseline <full.wasm>` | a `full` build of the same source, for the measured-elimination section of the report |
| `--target wasm` | the only accepted target |
| `--print-plan` | resolve and print the plan (identity, canonical ids, ids not included) without building |
| `--debug` | build without `--release` |

It needs the repository checkout, the `wasm32-unknown-unknown` target, the
matching `wasm-bindgen` CLI and `npm run js:build` (the wrapper is bundled from
the package's runtime with `esbuild`, a development dependency). From a webpack
or Vite build hook, call the same function; the consumer's own TypeScript or
JavaScript runs only here:

```js
// vite.config.js
import { buildCustomArtifact } from "./scripts/build-custom-artifact.mjs";

export default {
  plugins: [
    {
      name: "redact-secret-custom-artifact",
      async buildStart() {
        await buildCustomArtifact({ composition: "redact.composition.json", outDir: "src/vendor/redact" });
      },
    },
  ],
};
```

`buildCustomArtifact` resolves and validates first, then builds in the
workspace, then verifies, and only then replaces `outDir`. An unsupported id,
combination or target, a built registry or manifest that differs from the
resolved composition, a lock file that resolved a dependency differently, or an
artifact whose self-report differs fails the call with the output directory
untouched. It refuses to write into a non-empty directory that is not a
previous custom artifact.

### What is emitted

| File | Content |
| --- | --- |
| `index.js`, `index.d.ts`, `types/` | the wrapper a consumer imports: exactly the function set of `@redact-secret/core/common`, with `PROFILE` `"custom"` |
| `redact_secret_wasm_custom{.js,.d.ts,_bg.wasm,_bg.wasm.d.ts}` | the `wasm-bindgen` output for the web target |
| `artifact-manifest.custom.json` | the packaged `artifact-manifest/v1` (`artifact.variant` and `composition.profile` `custom`, `composition.kind` `custom`, `composition.id`, the exact included ids) |
| `capability-report.json` | included and not-included ids with pack and types, capabilities, the ceiling rules, the diagnostics a reader should expect, the retained engine floor, targets |
| `default-configuration.json` | the verified `config-snapshot/v1` of the artifact with no runtime input, read from the running artifact |
| `composition.json` | the canonical resolved input |
| `build-report.json` | engine source revision (null when the tree is dirty or not a repository), toolchain versions, composition and artifact identities, file digests, the bundled defaults, and the elimination measurement |

`build-report.json` keeps **bundled defaults** (`build-defaults/v1`: constants
in v1) apart from **measured elimination** (`elimination.measured` is `false`
and says why unless a baseline was supplied). Reproduction needs the same
engine source revision, toolchain and composition document; the manifest digest
and the composition identity are stable, byte-identical output across machines
is not promised.

### Using the artifact

```js
import { initialize, scanAndRedact, artifactManifest } from "./vendor/redact/index.js";

await initialize();                       // verifies the packaged manifest
artifactManifest().composition.id;        // custom:<sha256>
scanAndRedact(text, { actionPolicy });    // action policy per call, no rebuild
```

`initialize({ detection: { include } })` can only **narrow** within the included
detectors; a detector the artifact lacks is `INVALID_DETECTION_CONFIG`
(`DETECTOR_NOT_INCLUDED` through `resolveConfig`), never satisfied by loading
another artifact. A PII selection on a `pii: "none"` artifact is
`PII_SELECTOR_UNAVAILABLE`. A supported action policy, whole-input limits and a
ruleset are per call and need no rebuild; a policy never adds or removes a
finding. In Node the wrapper reads the `.wasm` bytes itself; in a browser or
bundler the glue resolves it relative to its own URL.

### Bundling with esbuild

The glue loads its binary with `new URL("redact_secret_wasm_custom_bg.wasm", import.meta.url)`, which no
bundler rewrites for you: the `.wasm` has to sit next to the emitted bundle. The qualified path is
**esbuild** (already a development dependency of this repository, so it needs nothing new and is
deterministic to install); this plugin, a thin build-time helper and not a UI, copies the binary:

```js
// A thin esbuild plugin for a generated custom artifact: esbuild bundles the glue but not the `.wasm` it
// loads relative to its own URL, so the plugin copies the artifact's binary next to the bundle.
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";

export function copyRedactWasm({ artifactDir }) {
  return {
    name: "redact-secret-wasm",
    setup(build) {
      build.onEnd((result) => {
        if (result.errors.length > 0) return;
        const outfile = build.initialOptions.outfile ?? join(build.initialOptions.outdir, "index.js");
        mkdirSync(dirname(outfile), { recursive: true });
        for (const name of readdirSync(artifactDir).filter((file) => file.endsWith("_bg.wasm"))) {
          copyFileSync(join(artifactDir, name), join(dirname(outfile), name));
        }
      });
    },
  };
}
```

```js
import { build } from "esbuild";
import { copyRedactWasm } from "./esbuild-redact-wasm.mjs";

await build({
  entryPoints: ["src/app.mjs"], // imports ./vendor/redact/index.js
  bundle: true,
  format: "esm",
  platform: "node", // or "browser"; the binary lands next to outfile either way
  outfile: "dist/app.mjs",
  plugins: [copyRedactWasm({ artifactDir: "src/vendor/redact" })],
});
```

`npm run configuration:qualify` bundles the installed standard package and a generated custom artifact
this way, runs both bundles and requires the same manifest digest as the unbundled artifact; the `browser`
build is checked for the binary reference and the copied bytes, and is not executed in a browser by that
step. The clean-install browser lane already bundles the *standard* package with Vite; webpack is not a
dependency of this repository and neither is qualified for a *custom* artifact here, so no recipe for them is
claimed; the same constraint (the binary beside the emitted glue) applies.

## How it works: the generation seam

The official detector tables are crate-private, so a consumer cannot name a
constructor, and filtering the full table at run time would keep every
detector reachable. The accepted seam is reviewed API, not textual patching:

1. `redact_secret::composition` publishes **one constructor per built-in
   detector**, named after the id with `-` written `_` (`github-token` is
   `github_token()`), each returning an opaque `SelectedDetector` that carries
   only that detector, its declared finding types (resolved at compile time) and
   its prefilter declaration. This is the whole accepted public naming; the
   module is the one added root name in `core-public-api`, and tests pin every
   constructor to its registration row, catalog entry and prefilter literals.
2. `Composition::new(name, pii, selected)` validates canonical order (a
   composition never reorders: registration order is the overlap tie breaker),
   no repeats, a valid name and a non-empty set (`InvalidDetector`), and derives
   the identity.
3. `DetectorRegistry::with_composition` (and `with_composition_and_pii`),
   `IncrementalSanitizer::with_composition_*` and `ArtifactManifest::custom`
   build the registry, the incremental session and the manifest from those
   constructors alone. A registry reports `Profile::Custom` (`"custom"`), which
   is not selectable by name; a custom detector cannot reuse any built-in id,
   selected or not.
4. The build script generates a leaf crate in the isolated workspace whose only
   source calls the selected constructors, plus a native helper that prints the
   manifest and the registry's ids so the build compares them with the plan
   before anything is emitted. The binding crate's third, mutually exclusive
   Cargo feature `custom` references no built-in constructor of its own; the
   leaf installs its composition and the packaged manifest bytes through
   `redact_secret_wasm::custom::install` from a `wasm-bindgen` start function.
5. The workspace copies the repository `Cargo.lock` and the `[profile.release]`
   section and is checked afterwards: it may add only the generated leaf.

Rust composes natively through the same constructors, with no script:

```rust
use redact_secret::composition::{self, Composition};
use redact_secret::DetectorRegistry;

let composition = Composition::new(
    "edge-checks",
    false,
    [composition::github_token(), composition::jwt(), composition::generic_token()],
)?;
let registry = DetectorRegistry::with_composition(&composition, [])?;
# Ok::<(), redact_secret::SecretScanError>(())
```

The core stays free of Cargo features; no `build.rs`, no `--cfg` flag and no
run-time filter is involved.

## The packaged manifest check

A custom artifact ships `artifact-manifest.custom.json` and embeds its exact
bytes. `initialize()` compares them with the manifest the artifact generates
from its own composition (`ArtifactManifest::verify_packaged`). A missing,
foreign (wrong schema) or non-matching document fails with the fixed
`ARTIFACT_MANIFEST_MISSING`, `ARTIFACT_MANIFEST_SCHEMA_MISMATCH` or
`ARTIFACT_MANIFEST_DIGEST_MISMATCH` from the binding, `INITIALIZATION_FAILED`
from the JavaScript wrapper, and nothing of either document is echoed. The
standard `full` and `common` artifacts keep the #1250 self-report check only
(schema, version, variant, own digest); no packaged file is shipped for them.

## Evidence

`npm run custom-composition:qualify` (builds two different compositions and the
`full` baseline, then runs everything below; it prints one JSON report and fails
on the first broken check). It is evidence for a reviewer, not a published
claim; record results in the issue or in `redact-secret-benchmarks`, not here. The installed-artifact
journeys (runtime overrides, sessions, comparison, bundlers) are in the
[configuration quickstart](configuration-quickstart.md#what-is-qualified).

- Agreement oracle: findings equal the `full` runtime artifact initialized with
  the same `include` over the canonical synchronous corpus; positive synthetic
  cases for selected detectors; excluded detectors never report and the weaker
  detector's finding equals the oracle's; incremental output equals the whole
  input output and the oracle's for chunks of 1, 13 and 200 UTF-16 code units.
- Manifest, registry and self-report name the same detectors; two different
  compositions have different identities, registries and manifests.
- Reachability against the produced binary, not the manifest: literals only an
  excluded detector's grammar carries (for example `sk_live_`, `xoxb-`,
  `glpat-`) are in the `full` binary and absent from the custom one, literals of
  selected detectors are present, the raw export surface is the standard glue's
  plus the module start hook, and the wrapper has exactly the names of
  `@redact-secret/core/common`. Identifier-like words and brotli sizes are
  reported against `full` and `common` as magnitudes.
- An unsupported id, a repeat, an empty set, an unknown member, a PII value and
  the unsupported targets fail before any file or workspace exists.
- A runtime action policy changes actions without a rebuild; a detector or PII
  selection above the ceiling is rejected and a narrowed owner cannot be
  silently widened (`DETECTION_CONFIG_CONFLICT`).

## Targets

| Target | Custom composition |
| --- | --- |
| WebAssembly (browser and Node fallback) | current: this guide |
| Rust | current, natively, through `redact_secret::composition` |
| Node addon | unsupported |
| Python wheel | unsupported: a server enforcement surface that stays `full` |
| CLI | unsupported: a server enforcement surface that stays `full` |

The full table is in the
[detector capability matrix](../reference/detector-capability-matrix.md#6-configuration-epic-1246-surface-matrix).
A consumer requirement with evidence reopens a row; there is no parity claim.
