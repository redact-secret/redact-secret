# Five-minute quickstart

[Documentation home](README.md) · [Installation](getting-started.md)

Each path below starts in an empty directory, installs only the published
package, and redacts one synthetic value. Pick the runtime you use; each one
takes about five minutes on a supported development machine, most of it
spent downloading packages or compiling.

| I use | Section | Installs |
| --- | --- | --- |
| Node.js 20, 22, or 24 | [Node.js](#nodejs) | `@redact-secret/core` from npm |
| Python 3.10 or newer | [Python](#python) | `redact-secret` from PyPI |
| A browser app with a bundler | [Browser with a bundler](#browser-with-a-bundler) | `@redact-secret/core` from npm |
| Rust | [Rust](#rust) | the `redact-secret` crate |
| CI, hooks, or shell pipelines | [Command line](#command-line) | the `redact-secret` binary, built from the `redact-secret-cli` crate |

## Which version you get

Every release so far is a beta; the stable `0.1.0` is not published yet. The
commands below pin the newest published beta, `0.1.0-beta.12` (PyPI spells it
`0.1.0b12`), so they give the same result tomorrow as today. Pin the version in
your own lockfile too.

- A bare `npm install @redact-secret/core` resolves the `latest` tag, which a
  maintainer moves by hand after each beta publish and which can lag the
  `beta` tag. `@beta` always selects the newest beta.
- A bare `pip install redact-secret` and `cargo add redact-secret` resolve the
  newest beta, because no stable release exists to prefer.
- `cargo install redact-secret-cli` without `--version` fails today
  (`could not find redact-secret-cli ... with version *`): Cargo does not
  choose a prerelease for an install unless you name it.
- When `0.1.0` is published, these pins change to `0.1.0` and the unpinned
  forms resolve it. The steps do not otherwise change. [Release
  status](releases/status.md) lists what each registry carries now.

Logging, tracing, MCP, and model-context packages ([integrations](integrations.md))
and the opt-in vault are separate packages on their own versions. They are not
part of these steps.

CI runs the Node.js, Python, and browser commands and files below against every
release candidate (see
[clean-install qualification](qualification.md#clean-install-qualification)).
It reads them from this page, so a change here changes the qualification too.
For the Rust and command-line sections CI checks the version pin and the page's
shape but does not execute them, because no candidate registry serves crates.
They were executed from this page's text against the published crates when
the page was last revised ([evidence](audits/evidence/1070/README.md)).
Commands are POSIX shell. On Windows, run them from Git Bash or WSL, or use
`.venv\Scripts\python` in place of `.venv/bin/python`.

## Node.js

Requires Node.js 20, 22, or 24. In an empty directory:

```sh qualify=node:setup
npm init -y
npm pkg set type=module
npm install @redact-secret/core@0.1.0-beta.12
```

Save this as `quickstart.mjs`:

```js qualify=node:file:quickstart.mjs
import { artifact, initialize, scanAndRedact, VERSION } from "@redact-secret/core";

await initialize();
const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");
console.log(`redact-secret ${VERSION} loaded ${artifact()}`);
console.log(result.text);
console.log(`findings: ${result.findings.length}`);
```

Run it:

```sh qualify=node:run
node quickstart.mjs
```

Expected output:

```text qualify=node:expect
redact-secret 0.1.0-beta.12 loaded addon
API_KEY=<SECRET_1>
findings: 1
```

`loaded addon` means npm installed the native addon for your platform. On a
platform without one, `initialize()` falls back to WebAssembly and the first
line ends in `loaded wasm` instead. If neither can load, `initialize()`
rejects with `INITIALIZATION_FAILED`; see
[troubleshooting](troubleshooting.md).

## Python

Requires CPython 3.10 or newer on a platform with a published wheel (see
[Python packaging](python-packaging.md)). In an empty directory:

```sh qualify=python:setup
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: redact-secret==0.1.0b12
```

`--only-binary=:all:` makes an unsupported platform fail during install
instead of attempting a source build. Save this as `quickstart.py`:

```python qualify=python:file:quickstart.py
import redact_secret

result = redact_secret.scan_and_redact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE")
print(f"redact-secret {redact_secret.VERSION}")
print(result.text)
print(f"findings: {len(result.findings)}")
```

Run it:

```sh qualify=python:run
.venv/bin/python quickstart.py
```

Expected output:

```text qualify=python:expect
redact-secret 0.1.0-beta.12
API_KEY=<SECRET_1>
findings: 1
```

## Browser with a bundler

This path uses [Vite](https://vite.dev), which honors the package's browser
conditions and emits the WebAssembly asset. In an empty directory:

```sh qualify=browser:setup
npm init -y
npm pkg set type=module
npm install @redact-secret/core@0.1.0-beta.12 vite@7.3.6
```

Save this as `index.html`:

```html qualify=browser:file:index.html
<!doctype html>
<meta charset="utf-8">
<title>Redact Secret quickstart</title>
<pre id="output">loading</pre>
<script type="module" src="/main.js"></script>
```

Save this as `main.js`:

```js qualify=browser:file:main.js
import { artifact, initialize, scanAndRedact, VERSION } from "@redact-secret/core";

const output = document.querySelector("#output");
try {
  await initialize();
  const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");
  output.textContent = [
    `redact-secret ${VERSION} loaded ${artifact()}`,
    result.text,
    `findings: ${result.findings.length}`,
  ].join("\n");
} catch (error) {
  output.textContent = `${error.code}: ${error.message}`;
}
```

Build it:

```sh qualify=browser:run
npx vite build
```

Serve the build, then open <http://localhost:4173/>:

```sh qualify=browser:serve
npx vite preview --port 4173 --strictPort
```

Expected page text:

```text qualify=browser:expect
redact-secret 0.1.0-beta.12 loaded wasm
API_KEY=<SECRET_1>
findings: 1
```

If the page shows `INITIALIZATION_FAILED`, check that the server returned the
`.wasm` asset with the `application/wasm` content type; see
[browser loading](guides/javascript.md#browser-loading).

## Rust

Requires Rust 1.88 or newer. In an empty directory:

```sh qualify=rust:setup
cargo new redact-quickstart
cd redact-quickstart
cargo add redact-secret@0.1.0-beta.12
```

Replace `src/main.rs` with:

```rust qualify=rust:file:src/main.rs
use redact_secret::{SecretScanError, VERSION, sanitize};

fn main() -> Result<(), SecretScanError> {
    let result = sanitize("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE")?;
    println!("redact-secret {VERSION}");
    println!("{}", result.text());
    println!("findings: {}", result.findings().len());
    Ok(())
}
```

Run it:

```sh qualify=rust:run
cargo run --quiet
```

Expected output:

```text qualify=rust:expect
redact-secret 0.1.0-beta.12
API_KEY=<SECRET_1>
findings: 1
```

`sanitize` uses the `full` profile, the default policy, and the default
limits. Custom policies, explicit limits, PII, and a registry reused across
scans use the [advanced API](guides/rust.md).

## Command line

Building the binary needs Rust 1.88 or newer. No prebuilt binary is published,
and `--version` is required while every release is a beta. In an empty
directory:

```sh qualify=cli:setup
cargo install redact-secret-cli --version 0.1.0-beta.12 --locked
```

Save this as `input.txt`:

```text qualify=cli:file:input.txt
API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE
```

Print the version, sanitize the file, then check it:

```sh qualify=cli:run
redact-secret --version
redact-secret --redact input.txt
redact-secret input.txt || echo "exit $?"
```

Expected output:

```text qualify=cli:expect
redact-secret 0.1.0-beta.12
API_KEY=<SECRET_1>
input.txt:8-39 contextual_secret detector=generic-token confidence=high action=redact obfuscation=none id=finding-1
exit 1
```

Check mode exits `1` when it finds anything, which is what makes it usable in
CI, and prints a one-line summary on standard error. `--redact` writes the
sanitized text to standard output, exits `0`, and never edits the input file.
Exit codes, reports, and limits are in the [CLI guide](guides/cli.md).

## Next steps

- [Policy and safe integration](guides/safe-integration.md): read this before
  sending sanitized output downstream. Scanning in a browser is preventive;
  scan again at the server, which is the authoritative enforcement boundary.
- The [JavaScript](guides/javascript.md), [Python](guides/python.md),
  [Rust](guides/rust.md), or [CLI](guides/cli.md) guide.
- [Streaming](guides/streaming.md), when the text arrives in chunks.
- [Integrations](integrations.md), for logs, traces, MCP, and model context.
- [Troubleshooting](troubleshooting.md), when something does not load or build.
