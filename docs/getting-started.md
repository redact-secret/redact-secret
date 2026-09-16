# Getting started

[Documentation home](README.md)

## Choose a runtime

| Runtime | Package / entry point | Current scope |
| --- | --- | --- |
| Node.js 20, 22, 24 | `@redact-secret/core` (ESM) | Whole-input and incremental; glibc Linux, macOS, Windows; x64 and arm64 |
| Browser | `@redact-secret/core` with WebAssembly | Whole-input and incremental; Chromium, Firefox, WebKit qualification |
| CPython 3.10+ | `redact-secret`, imported as `redact_secret` | Whole-input and incremental; see [wheel matrix](python-packaging.md) |
| Rust 1.88+ | `redact-secret`, imported as `redact_secret` | Whole-input and incremental |
| CLI | `redact-secret` binary | File checking/redaction and streamed standard input |

Node npm packages and CLI release binaries do not include musl/Alpine builds.
Python has a separate musllinux wheel matrix. A built test artifact is not
necessarily a distributed package; [qualification](qualification.md) explains
that distinction.

## Install a published release

The following versions were verified published on 2026-09-16; see
[release status](releases/status.md). npm `latest` still points to beta.1, so
select beta.3 explicitly rather than relying on an unqualified install.
Keep the selected version in your application's dependency lockfile.

```bash
npm install @redact-secret/core@0.1.0-beta.3
python -m pip install redact-secret==0.1.0b3
cargo add redact-secret@0.1.0-beta.3
cargo install redact-secret-cli --version 0.1.0-beta.3 --locked
```

Run only the command for your runtime. Rust library and CLI source installs
need a Rust toolchain; supported Python wheels and Node prebuilt addons do not.
Continue with [JavaScript](guides/javascript.md), [Python](guides/python.md),
[Rust](guides/rust.md), or [CLI](guides/cli.md).

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
