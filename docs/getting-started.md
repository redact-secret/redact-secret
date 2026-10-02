# Getting started

[Documentation home](README.md)

For a tested path from an empty directory to one redacted value, follow the
[five-minute quickstart](quickstart.md). This page lists the install commands,
the supported runtimes, and how to build this checkout.

## Install a published release

Every published release so far is a beta; the stable `0.1.0` is not published
yet. The commands below install the newest published beta, `0.1.0-beta.12`.
[Release status](releases/status.md) lists what the registries currently
carry. Select the version explicitly and keep it in your application's
dependency lockfile.

```bash
npm install @redact-secret/core@0.1.0-beta.12
python -m pip install redact-secret==0.1.0b12
cargo add redact-secret@0.1.0-beta.12
cargo install redact-secret-cli --version 0.1.0-beta.12 --locked
```

Run only the command for your runtime. What an unpinned install gives you
differs by registry, and the [quickstart](quickstart.md#which-version-you-get)
spells it out: npm resolves the `latest` tag, which maintainers move by hand;
pip and `cargo add` resolve the newest beta; `cargo install` fails without
`--version`. When `0.1.0` is published, the pins change to `0.1.0` and the
unpinned forms resolve it.

There is no prebuilt CLI binary to download: the CLI is built from the
`redact-secret-cli` crate, so it needs a Rust toolchain. The Rust library does
too. Supported Python wheels and Node prebuilt addons do not. Continue with
[JavaScript](guides/javascript.md), [Python](guides/python.md),
[Rust](guides/rust.md), or [CLI](guides/cli.md).

## Supported runtimes

| Runtime | Package / entry point | Current scope |
| --- | --- | --- |
| Node.js 20, 22, 24 | `@redact-secret/core` (ESM); `@redact-secret/core/common` (opt-in) | Whole-input and incremental; glibc and musl Linux, macOS, Windows; x64 and arm64; WebAssembly fallback elsewhere |
| Browser | `@redact-secret/core` with WebAssembly; `@redact-secret/core/common` (opt-in) | Whole-input and incremental; Chromium, Firefox, WebKit qualification; Cloudflare Workers via the `workerd` condition |
| CPython 3.10+ | `redact-secret`, imported as `redact_secret` | Whole-input and incremental; see [wheel matrix](python-packaging.md) |
| Rust 1.88+ | `redact-secret`, imported as `redact_secret` | Whole-input and incremental |
| CLI | `redact-secret` binary, built from `redact-secret-cli` | File checking/redaction and streamed standard input |

Not supported, or not claimed:

- **Vercel Edge.** Its runtime resolves the plain browser entry point, whose
  `fetch`-based initialization fails there. Cloudflare Workers is supported
  and verified; see [qualification](qualification.md) for the root cause.
- **A custom WebAssembly URL.** There is no public option to point
  `initialize()` at a different `.wasm` file; serve the asset the bundler
  emits.
- **Node.js outside 20, 22, and 24, and CPython older than 3.10.** The
  packages declare these ranges; other versions are not qualified.
- **A musl CLI binary.** No CLI binary is published for any target. Building
  the CLI from source on musl is not qualified. The npm addons do include musl
  Linux, and Python has a separate musllinux wheel matrix.
- **JavaScript or Python custom detector callbacks.** Use a
  [declarative ruleset](guides/rulesets.md); only Rust takes custom detectors.
- **Runtime network lookups, credential verification, and rotation.** The
  library never contacts a provider.

Where no Node.js addon loads, `initialize()` falls back to the WebAssembly
artifact, and `artifact()` reports `"addon"` or `"wasm"`. The musl addons, that
fallback, and Cloudflare Workers support are published starting with
0.1.0-beta.5. A built test artifact is not necessarily a distributed package;
[qualification](qualification.md) explains that distinction.

The `/common` entry point (Node and browser) is the opt-in `common`
detector profile: a smaller, structural/contextual-only detector set for
size- or latency-sensitive preventive consumers. Rust exposes the same profile
as `DetectorRegistry::with_common_built_in`. `full` — everything above
uses it by default — stays the first and simplest path, and is the only
profile Python and the CLI expose. See
[detector profiles in the JavaScript guide](guides/javascript.md#detector-profiles).

## Build this checkout

From the repository root, the CLI is the shortest path to the real Rust core:

```bash
cargo run --quiet --locked -p redact-secret-cli -- --help
printf '%s\n' 'API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE' | cargo run --quiet --locked -p redact-secret-cli -- --redact
```

Expected sanitized output: `API_KEY=<SECRET_1>`.

For Python, create an isolated environment and build the local extension:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install maturin pytest
maturin develop --manifest-path bindings/python/Cargo.toml
python -m pytest bindings/python/tests
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell.
For Rust applications, use a path dependency on `crates/secret-scan-core` while
working locally. JavaScript `npm run js:build` builds the wrapper only; it does
not install a native addon or build WebAssembly. Follow the
[local artifact qualification steps](qualification.md#running-it-locally) to
exercise the real Node or browser runtime from this checkout.
