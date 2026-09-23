# Five-minute quickstart

[Documentation home](README.md) · [Installation](getting-started.md)

Each path below starts in an empty directory, installs only the published
package, and redacts one synthetic value. Pick the runtime you use; each one
takes about five minutes on a supported development machine, most of it
spent downloading packages.

CI runs these exact commands and files against every release candidate (see
[clean-install qualification](qualification.md#clean-install-qualification)).
It reads them from this page, so a change here changes the qualification too.
Commands are POSIX shell. On Windows, run them from Git Bash or WSL, or use
`.venv\Scripts\python` in place of `.venv/bin/python`.

## Node.js

Requires Node.js 20, 22, or 24. In an empty directory:

```sh qualify=node:setup
npm init -y
npm pkg set type=module
npm install @redact-secret/core@0.1.0-beta.7
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
redact-secret 0.1.0-beta.7 loaded addon
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
.venv/bin/python -m pip install --only-binary=:all: redact-secret==0.1.0b7
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
redact-secret 0.1.0-beta.7
API_KEY=<SECRET_1>
findings: 1
```

## Browser with a bundler

This path uses [Vite](https://vite.dev), which honors the package's browser
conditions and emits the WebAssembly asset. In an empty directory:

```sh qualify=browser:setup
npm init -y
npm pkg set type=module
npm install @redact-secret/core@0.1.0-beta.7 vite@7.3.6
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
redact-secret 0.1.0-beta.7 loaded wasm
API_KEY=<SECRET_1>
findings: 1
```

If the page shows `INITIALIZATION_FAILED`, check that the server returned the
`.wasm` asset with the `application/wasm` content type; see
[browser loading](guides/javascript.md#browser-loading).

## Next steps

Read [policy and safe integration](guides/safe-integration.md) before sending
sanitized output downstream, then continue with the
[JavaScript](guides/javascript.md) or [Python](guides/python.md) guide.
Scanning in a browser is preventive; scan again at the server, which is the
authoritative enforcement boundary.
