/**
 * Installing a release candidate the way an outside consumer would, shared by
 * the qualification drivers that do it: `scripts/qualify-clean-install.mjs`
 * (issue #586, the quickstart) and `scripts/qualify-golden-path.mjs` (issue
 * #720, the MCP AI-context golden path).
 *
 * A candidate is the npm tarballs `scripts/pack-npm-candidate.mjs` packed from
 * the `node-addon`, `wasm-web`, and `wasm-web-common` artifacts of one
 * `artifact-qualification.yml` run, and/or that run's wheels. npm resolves the
 * `@redact-secret` scope from a local registry serving only those tarballs
 * (plus any other publish-shaped tarball a caller adds, such as a pinned
 * adapter); pip resolves from `PIP_FIND_LINKS` with `PIP_NO_INDEX`. What gets
 * installed is then checked byte for byte against the candidate files, and
 * every `.node`, `.wasm`, and `.whl` it carried is reported by SHA-256 so
 * `record-artifact-inventory.py` can require it to be an artifact that run
 * recorded.
 *
 * Every failure here is an `Error` whose message starts with `label`, names
 * no input, and carries no command output.
 */

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function makeAssert(label) {
  return (condition, message) => {
    if (!condition) throw new Error(`${label}: ${message}`);
  };
}

/** Every regular file under `root`, keyed by POSIX relative path, to its SHA-256. */
export async function fileDigests(root) {
  const digests = new Map();
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) digests.set(relative(root, path).split(sep).join("/"), sha256(await readFile(path)));
    }
  }
  await walk(root);
  return digests;
}

/**
 * A child environment with nothing that could point a command back into this
 * checkout: `npm run`'s own `npm_*` variables (its prefix is this
 * repository), Python path overrides, and an active virtualenv are dropped.
 */
export function cleanEnvironment(overrides) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(npm_|pip_|PYTHONPATH$|PYTHONHOME$|VIRTUAL_ENV$|NODE_PATH$|NODE_OPTIONS$|INIT_CWD$)/i.test(key)) continue;
    env[key] = value;
  }
  return { ...env, ...overrides };
}

/** Runs one shell block with `sh -e`; resolves with its outcome. */
export function runShell(block, cwd, env) {
  return new Promise((resolveRun, reject) => {
    const child = spawn("sh", ["-e", "-c", block], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) =>
      resolveRun({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
  });
}

/**
 * A fresh, empty `name` directory under a new OS temp directory, never
 * inside this checkout. The caller removes `parent`.
 */
export async function freshWorkspace(prefix, label, name = "project") {
  const assert = makeAssert(label);
  const parent = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  const repo = await realpath(REPO_ROOT);
  assert(!`${parent}${sep}`.startsWith(`${repo}${sep}`), "workspace is inside the repository");
  const project = join(parent, name);
  await mkdir(project);
  assert((await readdir(project)).length === 0, "workspace does not start empty");
  return { parent, project };
}

function tar(args) {
  return execFileSync("tar", args, { maxBuffer: 256 * 1024 * 1024 });
}

/**
 * The npm tarballs at `paths` by package name, each with the manifest it
 * carries, the digests npm will be told to expect, and its unpacked
 * contents keyed `<path inside package/>` to SHA-256.
 */
export async function loadNpmTarballs(paths, scratch, label) {
  const assert = makeAssert(label);
  const packages = new Map();
  for (const path of paths) {
    const file = basename(path);
    const bytes = await readFile(path);
    const manifest = JSON.parse(tar(["-xzOf", path, "package/package.json"]).toString("utf8"));
    assert(!packages.has(manifest.name), `${manifest.name} is supplied by two tarballs`);
    const unpacked = join(scratch, file.replace(/\.tgz$/, ""));
    await mkdir(unpacked, { recursive: true });
    tar(["-xzf", path, "-C", unpacked]);
    packages.set(manifest.name, {
      file,
      bytes,
      manifest,
      sha256: sha256(bytes),
      integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
      shasum: createHash("sha1").update(bytes).digest("hex"),
      contents: await fileDigests(join(unpacked, "package")),
    });
  }
  return packages;
}

/** Every `.tgz` in `candidateDir`, which must include `@redact-secret/core`. */
export async function loadNpmCandidate(candidateDir, scratch, label) {
  const files = (await readdir(candidateDir)).filter((name) => name.endsWith(".tgz")).sort();
  const packages = await loadNpmTarballs(files.map((file) => join(candidateDir, file)), scratch, label);
  makeAssert(label)(packages.has("@redact-secret/core"), `${candidateDir} holds no @redact-secret/core tarball`);
  return packages;
}

/**
 * A minimal npm registry for the `@redact-secret` scope that serves only the
 * given tarballs. A scope package with no tarball (another platform's
 * optional addon) is a 404, exactly as an unpublished name is.
 */
export async function startCandidateRegistry(packages) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://registry.invalid");
    const name = decodeURIComponent(url.pathname.slice(1));
    const tarball = url.pathname.startsWith("/-/tarballs/")
      ? [...packages.values()].find((entry) => entry.file === basename(url.pathname))
      : undefined;
    if (tarball !== undefined) {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(tarball.bytes);
      return;
    }
    const entry = packages.get(name);
    if (entry === undefined) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not found"}');
      return;
    }
    const { version } = entry.manifest;
    const base = `http://127.0.0.1:${server.address().port}`;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        name,
        "dist-tags": { latest: version },
        versions: {
          [version]: {
            ...entry.manifest,
            _id: `${name}@${version}`,
            dist: { tarball: `${base}/-/tarballs/${entry.file}`, integrity: entry.integrity, shasum: entry.shasum },
          },
        },
      }),
    );
  });
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return {
    url: `http://127.0.0.1:${server.address().port}/`,
    close: () => new Promise((resolveClose) => server.close(resolveClose)),
  };
}

/**
 * The installed `@redact-secret` packages must be exactly the wrapper, the
 * WebAssembly package, this host's addon package, and any `additional`
 * names; each must have come from the expected registry at the expected
 * integrity; and each package's files -- the addon and both `.wasm` builds
 * included -- must be the candidate's bytes (or, from the public registry,
 * carry every declared runtime file). `candidate` supplies the expected
 * tarball of every one of those packages when it is defined.
 */
export async function verifyNpmInstall(project, version, candidate, registryUrl, { label, additional = [] }) {
  const assert = makeAssert(label);
  const scopeDir = join(project, "node_modules", "@redact-secret");
  const { resolveAddonSpecifier } = await import(
    pathToFileURL(join(scopeDir, "core", "dist", "runtime", "node.js")).href
  );
  const hostAddon = resolveAddonSpecifier();
  assert(hostAddon !== undefined, `no addon package is mapped for ${process.platform}/${process.arch}`);
  const product = ["@redact-secret/core", "@redact-secret/wasm", hostAddon];
  const expected = [...product, ...additional].sort();
  const installed = (await readdir(scopeDir)).map((name) => `@redact-secret/${name}`).sort();
  assert(
    JSON.stringify(installed) === JSON.stringify(expected),
    `installed ${installed.join(", ")}, expected ${expected.join(", ")}`,
  );

  const lock = JSON.parse(await readFile(join(project, "package-lock.json"), "utf8"));
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    assert(entry.link !== true && !String(entry.resolved ?? "").startsWith("file:"), `${key} is a local link`);
  }
  const packages = [];
  for (const name of expected) {
    const dir = join(scopeDir, name.split("/")[1]);
    const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
    const locked = lock.packages?.[`node_modules/${name}`];
    const expectedVersion = product.includes(name) ? version : candidate?.get(name)?.manifest.version;
    assert(manifest.version === expectedVersion && locked?.version === expectedVersion, `${name} is not ${expectedVersion}`);
    assert(String(locked.resolved).startsWith(registryUrl), `${name} was not resolved from ${registryUrl}`);
    const contents = await fileDigests(dir);
    const required =
      name === hostAddon
        ? [manifest.main]
        : name === "@redact-secret/wasm"
          ? manifest.files
          : name === "@redact-secret/core"
            ? ["dist/index.js", "dist/common.js", "dist/runtime/node.js", "dist/runtime/browser.js"]
            : [];
    for (const file of required) assert(contents.has(file), `${name} is missing runtime file ${file}`);
    if (candidate !== undefined) {
      const source = candidate.get(name);
      assert(source !== undefined, `${name} has no candidate tarball`);
      assert(locked.integrity === source.integrity, `${name} integrity differs from the candidate tarball`);
      const same =
        contents.size === source.contents.size &&
        [...source.contents].every(([file, digest]) => contents.get(file) === digest);
      assert(same, `${name}'s installed files differ from the candidate tarball`);
    }
    packages.push({
      name,
      version: expectedVersion,
      file: candidate?.get(name)?.file ?? null,
      sha256: candidate?.get(name)?.sha256 ?? null,
      integrity: locked.integrity,
    });
  }
  const binaries = [];
  for (const [name, dir] of [[hostAddon, hostAddon.split("/")[1]], ["@redact-secret/wasm", "wasm"]]) {
    const contents = await fileDigests(join(scopeDir, dir));
    for (const [file, digest] of contents) {
      if (file.endsWith(".node") || file.endsWith(".wasm")) binaries.push({ package: name, file, sha256: digest });
    }
  }
  assert(binaries.filter((binary) => binary.file.endsWith(".wasm")).length === 2, "the wasm package does not carry both profiles");
  return { hostAddon, packages, binaries };
}

/**
 * The probe that describes the installed distribution and matches it to a
 * candidate wheel lives in `scripts/lib/installed_wheel_probe.py`, so its
 * wheel-selection rule can be unit tested without a built wheel (issue #687).
 * Its source is passed to the candidate environment's interpreter with
 * `python -c`, which needs no file inside the throwaway project.
 */
export const wheelProbeSource = () => readFile(join(REPO_ROOT, "scripts", "lib", "installed_wheel_probe.py"), "utf8");

export function sourceCommit() {
  if (process.env.SOURCE_COMMIT?.trim()) return process.env.SOURCE_COMMIT.trim();
  return execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
}
