---
decision_id: decision-define-detector-profile-and-pack-contract
status: accepted
scope: workspace
title: Define the detector profile and pack contract
decided_at: 2026-09-18
---

# Define the detector profile and pack contract

Issue [#379](https://github.com/redact-secret/redact-secret/issues/379), under
epic [#377](https://github.com/redact-secret/redact-secret/issues/377). The
evidence is the measured baseline from
[#378](https://github.com/redact-secret/redact-secret/issues/378),
[`docs/audits/evidence/378/README.md`](../audits/evidence/378/README.md). This
record fixes the contract that #380 (registry composition), #381 (full and
common WebAssembly artifacts), and #382 (qualification) implement. It changes no
detector, public API, artifact, or release by itself, and authorizes no release.

## Context

The built-in registry is one private list of 42 detectors in canonical order,
reached only through `DetectorRegistry::with_built_in`. Every binding and the CLI
build that same registry. Issue #378 measured, from real compiled artifacts:

| Composition | Detectors | WASM raw | WASM brotli | vs. `full` (raw / brotli) |
| --- | --- | --- | --- | --- |
| `full` | 42 | 281,346 B | 77,407 B | baseline |
| structural/contextual only | 6 | 224,879 B | 65,235 B | −20.1% / −15.7% |
| no detectors (engine floor) | 0 | 156,857 B | 45,183 B | −44.2% / −41.6% |

The structural/contextual composition is the only one whose processing time
was lower in every whole-input and streaming measurement. Removing any one of
the five illustrative vendor groups saved at most 6.53% of raw WASM size
(`cloud`, 14 detectors), with per-detector cost roughly uniform across groups
and runtime differences inside 10-run noise. The engine floor is 55–58% of
`full`, and no detector composition can remove it.

Link-time reachability already removes detector code: #378 built every variant
by removing constructor calls, with the existing release profile (`lto = "fat"`,
`codegen-units = 1`) and no Cargo feature, `wasm-opt` pass, or source split.

## Decision

Two **profiles** are supported: `full`, the default, and `common`. Their
membership comes from exactly two internal **packs**. Compile-time composition
works through **reachability of a per-profile registry constructor**. It does
not use Cargo features on the published crates. Runtime detector selection by
detector id is not offered on any surface.

### Terms

- A **pack** is an internal, non-published tag on each built-in detector. It
  says which profiles contain that detector. Every built-in detector has exactly
  one pack.
- A **profile** is a named, reviewed set of packs. Its registry holds those
  packs' detectors in canonical order. Profiles are the only unit that
  consumers select, qualify, or document.
- The **canonical order** is the existing `built_in_detectors()` order, the
  fourth overlap tie breaker. There is one canonical order, and each profile
  uses a subsequence of it.

### Profile semantics

- **`full`** holds every officially supported built-in detector: today the
  `common` pack plus the `provider` pack, 42 detectors. It stays the default on
  every surface: `DetectorRegistry::with_built_in`, the `@redact-secret/core`
  root entry, the Python package, and the CLI. Its membership, order, and
  findings are the compatibility baseline. This decision changes none of them.
- **`common`** holds only the `common` pack: detectors that recognize a
  structure or a credential-bearing context rather than one issuer's token
  format. It is meant for size- or latency-sensitive **preventive** consumers,
  mainly browser UX and small agent or tool processes. It is not a server
  enforcement profile. The authoritative server boundary in `ARCHITECTURE.md`
  should run `full`.

Profiles are nested (`common` ⊂ `full`). A new profile must be a union of
declared packs. Consumers never compose profiles at build time.

### Pack membership

| Pack | Rule | Members today |
| --- | --- | --- |
| `common` | Format-agnostic: the grammar is a published structure (PEM/OpenSSH key, RFC 7519 JWT, `otpauth://` URI, credential-bearing connection URI) or a credential-bearing context (HTTP `Bearer` authorization, contextual assignment). It is not tied to one issuer's prefix, marker, or length. | `private-key`, `jwt`, `bearer-token`, `connection-string`, `otpauth-uri`, `generic-token` (6) |
| `provider` | The grammar is defined by one issuer's documented or reviewed token format. This includes context-gated provider shapes such as `twilio-auth-token` and `new-relic-license-key`. | The other 36 built-in detectors, including edge cases `vault-token` (HashiCorp-specific prefixes) and `google-api-key` (one issuer, many products) |

Admission rules:

1. Every new built-in detector declares its pack in the change that adds it.
   The default is `provider`.
2. A detector joins `common` only if it meets the `common` rule and the change
   states its measured size and processing cost. `common` detectors are about
   3.8× heavier in compiled code than the 42-detector average (≈11.3 KB raw
   each versus ≈3.0 KB), so `common` is the artifact where growth is felt.
3. Detectors that feed incremental retention stay in `common`. Today these are
   `private-key` (retention tracker), `bearer-token` (open authorization), and
   `generic-token` (open contextual assignment). The shared retention reserve
   sized for `full` is valid for every subset. Retaining more than a subset
   needs changes memory and emission timing, never output.
4. A `common` detector must not depend on a `provider` detector's module. If it
   did, the `provider` code would be linked into every `common` artifact. Shared
   lexical helpers such as `detectors::text` are engine code, not pack code.

### Compile-time composition mechanism

The core crate (`redact-secret`) keeps its policy of **no Cargo features**.
There is still one shape of that crate, and it is the one the tests exercise.

- The core keeps the pack tag in one private, checked-in membership table
  beside `built_in_detectors()`. It is not generated by a build script.
- The core exposes **one registry constructor per profile**.
  `with_built_in(custom)` stays `full`, unchanged. A `common` constructor is
  added. Its exact name is fixed by #380 through the reviewed `core-public-api`
  manifest.
- **Reachability rule:** a smaller profile's constructor must not reference any
  constructor outside its membership, even through a runtime `match` on a
  profile value. An artifact that references only the `common` constructor then
  links no `provider` code, with no reliance on constant propagation.
  Qualification enforces this by size (see below).
- The core exposes a public profile identity: the profile names `full` and
  `common`, and the profile a registry was built from. Bindings report it, and
  tests assert it.

The private WebAssembly binding crate (`bindings/wasm`, a `cdylib` leaf that no
crate depends on) chooses which constructor it references. It uses one
**additive, default-on** Cargo feature, `full`. The default build is `full` and
unchanged. The `common` artifact is built with `--no-default-features`. No other
feature is introduced in any crate for profile selection.

### Cargo feature unification

Cargo unifies features across a dependency graph, and features can only add.
This mechanism is designed around both facts:

- The core has no profile features, so one dependent can never change the
  profile another dependent gets. A binary that references only the `common`
  constructor links only `common` detectors. If another crate in the same
  program calls `with_built_in`, the program links both sets. That is correct
  for a program that uses both, and each registry still behaves as its own
  profile. Nothing is ever silently removed.
- The only profile feature sits on a leaf crate that has no dependents, so
  unification cannot reach it from outside. Inside the workspace, the only way
  to change it is on that crate's own command line (`--all-features`, or
  forgetting `--no-default-features`). Either mistake turns a `common` build
  into `full`: more detection, never less. The artifact's self-reported profile
  check (below) makes that mistake fail qualification instead of shipping.
- There is no feature per vendor and no feature per pack. The #378 data does not
  justify either, and the combinations could not be qualified (2⁴² id subsets,
  or 2ⁿ pack subsets).

### Determinism and overlap

- A profile's registry is the canonical order filtered to its packs, in the
  same relative order. The fourth tie breaker therefore ranks any two detectors
  the same way in every profile that holds both.
- **Per-detector invariance:** for every detector *D* in profile *P* and every
  input, *D*'s candidates in *P* are exactly its candidates in `full`. A
  detector's behavior changes only through its own reviewed change, which
  applies to every profile at once. A profile never changes what a detector id
  means.
- **Profile findings differ from `full` by design.** Overlap resolution is
  global, so removing competitors changes which candidate wins. In `common`, a
  provider token inside an assignment or `Bearer` header can come back as
  `generic-token` or `bearer-token`, with that detector's type, confidence, and
  so possibly a different default-policy action. For example, a `warn` can
  appear where `full` would `redact`. A bare provider token outside any such
  context is not detected at all. This is the false-negative cost of `common`.
  Its false-positive rate is not higher, because it only drops candidates.
- `common` findings are deterministic and qualified against their own reviewed
  expectations (see [Qualification obligations](#qualification-obligations)),
  not derived from `full` at runtime.

### Custom detectors

Custom detectors remain a native Rust extension only. No binding exposes a
custom detector callback (`decision-define-runtime-bindings`).

- Every profile constructor registers the profile's built-in detectors first,
  in canonical order, then the custom detectors in the order given. This is the
  same rule `with_built_in` follows today.
- **Reserved ids:** a profile constructor rejects, with `InvalidDetector`, a
  custom detector whose id matches *any* `full` built-in id, including ids
  outside that profile. Otherwise a custom `github-token` in `common` would
  emit findings under a built-in id with different behavior.
- The existing low-level path (`DetectorRegistry::new()` plus `register`) is
  unchanged. It carries no profile identity and no profile guarantee.
  Tightening it would be a separate, breaking API change.

### Runtime surfaces

| Surface | Profiles | How selected | Rationale |
| --- | --- | --- | --- |
| Rust crate | `full`, `common` | Which constructor the caller references. The linker keeps only what is referenced. | Small native agents get real size savings without features. |
| JavaScript, browser | `full`, `common` | Import entry: `@redact-secret/core` (full, unchanged) or `@redact-secret/core/common`. Each entry loads its own compiled WebAssembly. | Transfer size is the measured win, and it needs a different artifact. Runtime selection inside one module would not shrink it. |
| JavaScript, Node | `full`, `common` | Same two entries. The existing N-API addon builds the registry for whichever profile was imported. | Native addon size is not transfer size, so a second set of six platform addons is not justified. Isomorphic code importing `/common` gets the same findings in Node and the browser. |
| Python | `full` only | None. Intentionally no `profile` argument. | Server-side and authoritative use should run `full`, and wheel size is not a measured constraint. Adding it later is additive. |
| CLI | `full` only | None. Intentionally no `--profile` flag. | The CLI is a pre-commit and CI enforcement tool. A smaller profile would only weaken enforcement. |

Each JavaScript entry exports a `PROFILE` constant (`"full"` or `"common"`).
`initialize()` rejects with `INITIALIZATION_FAILED` when the loaded artifact
reports a different profile, the same way a version mismatch is rejected today.
A future profile that a runtime does not support is left out of that runtime's
export conditions, so the import fails to resolve. It never falls back to
another profile.

### WebAssembly artifact naming and import

- `@redact-secret/wasm` stays the one WebAssembly dependency package. Its root
  entry and `redact_secret_wasm_bg.wasm` stay the `full` artifact, byte-for-byte
  on the unchanged path. The `common` artifact ships in the same package under a
  `common` subpath export, with its own glue and `.wasm` file (for example,
  `redact_secret_wasm_common_bg.wasm`).
- `@redact-secret/core` adds a `./common` export and matching internal
  `#native-common` import conditions. The root export, its types, and its
  `#native` map are unchanged, so the default path is no harder than before.
- A bundler includes only the `.wasm` file that the chosen entry imports. The
  cost is install size: about 254 KB more on disk (the 224,879 B `common`
  `.wasm` plus its ≈29 KB glue) for every installer of `@redact-secret/wasm`. This is accepted instead of adding a registry name, a
  lockstep manifest, and a release job for a separate `@redact-secret/wasm-common`.

### Named packs beyond `common`

No named vendor pack (AI, cloud, source-control, package-registry, SaaS) ships
now. The largest measured group saves 6.53% of raw WASM size, less than half of
what `common` saves. Its runtime effect cannot be told apart from noise, and no
concrete consumer has asked for it. The mechanism above keeps adding one cheap:
add a pack tag, add a constructor that obeys the reachability rule, and add one
WebAssembly subpath.

Re-measure with `scripts/measure-detector-cost.mjs` and revisit this section
when any trigger fires:

1. the built-in count reaches 63 (1.5× the 42-detector baseline);
2. `full` WebAssembly brotli size grows 25% over the #378 baseline, to
   96,759 B or more; or
3. an issue names a consumer, its runtime, and a byte or latency budget that
   `common` misses on coverage and `full` misses on cost.

A named pack is justified only when trigger 3 applies **and** removing the
candidate group from `full` saves at least 10% of `full`'s brotli WebAssembly
size in a fresh measurement.

## Versioning and compatibility

The product keeps one lockstep SemVer version
(`decision-release-bindings-in-lockstep`). Pack and profile changes are
classified as follows, and each change's changelog entry states its class.

| Change | Class |
| --- | --- |
| Add a built-in detector to `provider` | Minor: `full` gains coverage. `common` is unaffected. |
| Add a built-in detector to `common` | Minor: both profiles gain coverage. Refresh `common` expectations. |
| Move a detector `provider` → `common` | Minor: `common` gains coverage, and overlap outcomes in `common` may change. `full` is unaffected because canonical order and membership are unchanged. |
| Move a detector `common` → `provider` | Breaking for `common` consumers: `common` loses coverage. |
| Remove a detector from `full` | Breaking: `full` must hold every officially supported built-in. |
| Reorder the canonical order | Breaking: an existing conformance-contract change, unchanged by this decision. |
| Change one detector's grammar | Governed by that detector's own contract. It applies identically in every profile that holds the detector. |

A pack move never changes the canonical order, because a pack is a tag, not a
position. Before 1.0, a breaking class may ship in a prerelease bump, but the
changelog must still call it breaking.

## Migration strategy

Existing consumers do nothing. Every default stays `full` with identical
findings. `common` is opt-in: change the import to `@redact-secret/core/common`,
or call the `common` Rust constructor. Delivery order:

1. **#380:** add the membership table, the `common` constructor under the
   reachability rule, profile identity, reserved-id rejection, and the core
   tests below. `full` behavior must stay byte-identical on the canonical corpus.
2. **#381:** build the `common` WebAssembly artifact through the leaf-crate
   feature and measure it against `full` with the #378 tooling. The size and
   runtime win must be confirmed on the real artifact before publication.
3. **#382:** qualify `common` on every surface that exposes it, then add the
   `./common` package exports. Nothing public ships a `common` entry before
   #382 qualification passes.

User documentation leads with the default `full` path. `common` is documented
as an opt-in preventive profile with its false-negative tradeoff stated.

## Qualification obligations

For every supported profile and surface that exposes it:

1. **Membership:** `full`'s ids equal the canonical 42-id list in order.
   `common`'s ids equal its declared list and form an order-preserving
   subsequence of `full`. Every built-in has exactly one pack.
2. **Per-detector invariance:** over the canonical corpus, each `common`
   detector's candidates in `common` equal its candidates in `full`.
3. **Findings:** the whole canonical corpus runs under `common` on the Rust core,
   the `common` WebAssembly artifact, and the Node `/common` entry. It is checked
   against reviewed, committed `common` expectations kept beside the canonical
   fixtures, not recomputed by the runner. Incremental partition equivalence
   holds for `common` as it does for `full`.
4. **Reserved ids:** each profile constructor rejects a custom detector that
   reuses any built-in id.
5. **Artifact identity:** each WebAssembly artifact reports its profile, and the
   facade rejects a mismatch. The artifact inventory records each artifact's
   profile, SHA-256, raw size, and brotli size.
6. **Reachability guard:** the `common` WebAssembly artifact must be smaller
   than `full`, and must not exceed the #381 measured size by more than an
   explicitly reviewed margin. A regression means `provider` code became
   reachable from the `common` constructor.
7. **Default unchanged:** `full` artifacts, findings, and exports match the
   pre-change baseline.

## Rejected alternatives

- **Cargo features on the core crate** (one per pack or per vendor). This would
  break the core's one-shape policy. Unification would let any dependency that
  enables the defaults quietly re-add every detector, so a smaller profile could
  never be guaranteed downstream. Features only add, while a smaller profile
  needs to subtract. The test matrix would grow with every feature.
- **One crate or npm package per vendor or per pack.** This adds registry names,
  lockstep manifests, and release jobs to save at most ≈1.6 KB raw per vendor
  detector (measured group averages ranged from ≈0.2 to ≈1.6 KB). #377 and this
  issue both rule it out.
- **Runtime-only profile selection as the browser mechanism.** The whole module
  would still be downloaded (#377: runtime selection alone is not enough). It is
  kept only where size does not matter: the Node addon, whose semantics match
  the compiled `common` artifact.
- **Runtime allow or deny lists by detector id.** These create unqualifiable
  combinations and change overlap outcomes without review. They also invite
  silent coverage loss at enforcement boundaries.
- **A `build.rs`-generated registry from an external manifest.** This adds a
  build script to the core and gains nothing with two packs. A checked-in table
  is reviewable in the same diff as the detector.
- **`RUSTFLAGS --cfg` profile selection.** It is invisible in manifests, applies
  to every crate in the build, and is hard to audit in qualification.
- **A separate `@redact-secret/wasm-common` package.** It would cost another
  name, lockstep manifest, and publish job, only to save install size, which is
  not the constraint.
- **Naming the small profile `tiny`.** The name describes size rather than
  membership, and it would become wrong as `common` grows. `tiny` stays the
  informal name for the artifact in #381.

## Non-goals

- No crate or npm package per vendor, and no feature per vendor.
- No dynamic, network-loaded, or user-supplied rule packs or plugins.
- No online credential validation.
- No custom detector callbacks across FFI, and no user-composed profiles.
- No `common` profile for Python or the CLI in this contract.
- No change to `full` membership, canonical order, findings, or default exports.
- No release, version choice, or publication. That remains under
  `AGENTS.md` release authority.

## Consequences

Detector coverage can grow in `full` without affecting `common` consumers.
`common` gives browser and small native consumers about 16% less transfer size
and lower scan cost now. The engine floor, 55–58% of `full`, caps what any
profile can save. Declarative provider-rule tables, which #377 left for separate
investigation, are the lever if that floor or per-detector code duplication
becomes the dominant cost. Every future profile adds a conformance expectation
set, an artifact, and a qualification row, which is why profiles stay few and
evidence-gated.
