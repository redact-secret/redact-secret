// Same-process isolation probe for the Node N-API addon (issue #1221).
//
//   cargo build -p redact-secret-node --release --locked
//   cp target/release/libredact_secret_node.dylib <dir>/redact-secret.node   # .so on Linux
//   node docs/audits/evidence/1221/probe-node.mjs <dir>/redact-secret.node
//
// The addon keeps its registry and PII-selection cells in thread-locals, so a
// Worker is an independent configuration owner. This probe uses that to run
// A (PII off), B (pii:global) and C (network-address only) in one process.
// Every credential and PII value is synthetic and assembled at run time.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const ADDON = process.argv[2] ?? workerData?.addon;
const EMAIL = "email: owner.synthetic@mail-synthetic.org";
const IP = "client_ip = 192.168.1.7";
const TOKEN_LINE = `API_KEY=${["ghp", "_SYNTHETICREVOKED", "0".repeat(20)].join("")}`;
const ruleset = (prefix) =>
  Buffer.from(
    `ruleset-revision: 1\ndetector: acme-${prefix.toLowerCase()}\nspecificity: contextual\nprefix: "${prefix}_"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n`,
  );
const R1 = ruleset("ACMEONE");
const R2 = ruleset("ACMETWO");
const R1_TEXT = `v = ACMEONE_${"abcdefghij".repeat(3)}`;
const R2_TEXT = `v = ACMETWO_${"abcdefghij".repeat(3)}`;
const LIMITS = {
  maxInputCodeUnits: 32768,
  maxBufferedCodeUnits: 16512,
  maxTokenCodeUnits: 8192,
  maxMultilineCodeUnits: 16384,
};
const SELECTION = { A: null, B: ["pii:global"], C: ["pii:family:global:network-address"] };

const types = (findings) => findings.map((f) => f.type).sort();
const attempt = (fn) => {
  try {
    return { ok: fn() };
  } catch (e) {
    return { err: e.code ?? String(e.message).slice(0, 80) };
  }
};

if (!isMainThread) {
  const addon = createRequire(import.meta.url)(ADDON);
  const sessions = new Map();
  const handlers = {
    configure({ role }) {
      if (SELECTION[role] === null) addon.initialize();
      else addon.initializePii(SELECTION[role]);
      return addon.piiActivation();
    },
    scan({ text, ruleset: bytes }) {
      return types(addon.scan(text, undefined, undefined, bytes ? Buffer.from(bytes) : undefined));
    },
    open({ id }) {
      sessions.set(id, addon.createIncrementalSanitizer({ limits: LIMITS }));
      return "open";
    },
    append({ id, chunk }) {
      const r = sessions.get(id).append(chunk);
      return { text: r.text, types: types(r.findings) };
    },
    finish({ id }) {
      const r = sessions.get(id).finalize();
      return { text: r.text, types: types(r.findings) };
    },
    attempt({ call, args }) {
      return attempt(() => {
        const v = addon[call](...args);
        return v === undefined ? "ok" : v;
      });
    },
    activationUnconfigured() {
      return addon.piiActivation();
    },
  };
  parentPort.on("message", ({ op, ...rest }) => {
    try {
      parentPort.postMessage({ result: handlers[op](rest) });
    } catch (e) {
      parentPort.postMessage({ error: e.code ?? String(e.message).slice(0, 100) });
    }
  });
} else {
  const spawn = () => {
    const worker = new Worker(new URL(import.meta.url), { workerData: { addon: ADDON }, argv: [] });
    const ask = (op, args = {}) =>
      new Promise((resolve) => {
        worker.once("message", resolve);
        worker.postMessage({ op, ...args });
      });
    return { worker, ask };
  };
  const record = (name, value) => console.log(`${name}: ${JSON.stringify(value)}`);
  const main = createRequire(import.meta.url)(ADDON);
  record("addon.version", main.version());
  const count = async (x, text, bytes) => (await x.ask("scan", { text, ruleset: bytes && [...bytes] })).result.length;

  // 1. A, B and C alive together in one process.
  const w = { A: spawn(), B: spawn(), C: spawn() };
  for (const role of ["A", "B", "C"]) record(`configure.${role}`, (await w[role].ask("configure", { role })).result);
  const seen = {};
  for (const role of ["A", "B", "C"]) {
    seen[role] = { email: await count(w[role], EMAIL), ip: await count(w[role], IP), token: await count(w[role], TOKEN_LINE) };
  }
  record("concurrent.findingCounts", seen);
  assert.equal(seen.A.email, 0);
  assert.equal(seen.A.ip, 0);
  assert.ok(seen.B.email > 0 && seen.B.ip > 0);
  assert.equal(seen.C.email, 0);
  assert.ok(seen.C.ip > 0);
  assert.ok(seen.A.token > 0 && seen.B.token > 0 && seen.C.token > 0);
  // The main thread was never configured and is unaffected by the workers.
  record("main.unconfigured.emailFindings", main.scan(EMAIL).length);
  assert.equal(main.scan(EMAIL).length, 0);

  // 2. Streams interleaved across A/B/C; the email is split across a chunk boundary.
  for (const role of ["A", "B", "C"]) await w[role].ask("open", { id: "s" });
  const half = EMAIL.indexOf("@") + 3;
  const streams = { A: [], B: [], C: [] };
  for (const chunk of [EMAIL.slice(0, half), EMAIL.slice(half), `\n${IP}\n`]) {
    for (const role of ["A", "B", "C"]) streams[role].push(...(await w[role].ask("append", { id: "s", chunk })).result.types);
  }
  for (const role of ["A", "B", "C"]) streams[role].push(...(await w[role].ask("finish", { id: "s" })).result.types);
  record("streams.findingTypesAcrossAppendsAndFinalize", streams);
  assert.equal(streams.A.length, 0);
  assert.ok(streams.B.length >= 2);
  assert.ok(streams.C.length >= 1 && streams.C.length < streams.B.length);

  // 3. Rulesets alternate R1/R2 in every worker; the PII selection survives a ruleset scan.
  const rs = {};
  for (const role of ["A", "B", "C"]) {
    rs[role] = {
      r1_on_r1: await count(w[role], R1_TEXT, R1),
      r2_on_r1: await count(w[role], R2_TEXT, R1),
      r2_on_r2: await count(w[role], R2_TEXT, R2),
      r1_again: await count(w[role], R1_TEXT, R1),
      emailWithRuleset: await count(w[role], EMAIL, R1),
    };
  }
  record("rulesets.counts", rs);
  for (const role of ["A", "B", "C"]) {
    assert.ok(rs[role].r1_on_r1 > 0 && rs[role].r2_on_r2 > 0 && rs[role].r1_again > 0);
    assert.equal(rs[role].r2_on_r1, 0);
  }
  assert.equal(rs.A.emailWithRuleset, 0);
  assert.ok(rs.B.emailWithRuleset > 0);
  assert.equal(rs.C.emailWithRuleset, 0);

  // 4. Legacy contract inside worker B: equivalent selection is idempotent, a differing one conflicts.
  const legacy = {
    equivalent: (await w.B.ask("attempt", { call: "initializePii", args: [["pii"]] })).result,
    differing: (await w.B.ask("attempt", { call: "initializePii", args: [SELECTION.C] })).result,
    offAfterOn: (await w.B.ask("attempt", { call: "initialize", args: [] })).result,
    onAfterOff: (await w.A.ask("attempt", { call: "initializePii", args: [SELECTION.B] })).result,
  };
  record("legacy.conflicts", legacy);
  assert.ok("ok" in legacy.equivalent);
  assert.ok("err" in legacy.differing && "err" in legacy.offAfterOn && "err" in legacy.onAfterOff);
  assert.ok((await count(w.B, EMAIL)) > 0);
  assert.equal(await count(w.A, EMAIL), 0);

  // 5. Teardown: terminate B; a fresh worker starts clean, A and C are untouched.
  await w.B.worker.terminate();
  const fresh = spawn();
  record("teardown.freshWorkerActivationBeforeConfigure", (await fresh.ask("activationUnconfigured")).result);
  record("teardown.thenPiiSelectionAfterThatRead", (await fresh.ask("attempt", { call: "initializePii", args: [SELECTION.C] })).result);
  const fresh2 = spawn();
  record("teardown.freshWorkerConfigureC", (await fresh2.ask("configure", { role: "C" })).result);
  assert.equal(await count(w.C, EMAIL), 0);
  assert.ok((await count(w.C, IP)) > 0);

  // 6. Construction-order permutations: every order yields identical per-role results.
  const orders = [["A", "B", "C"], ["A", "C", "B"], ["B", "A", "C"], ["B", "C", "A"], ["C", "A", "B"], ["C", "B", "A"]];
  const signatures = new Set();
  for (const order of orders) {
    const ws = {};
    for (const role of order) {
      ws[role] = spawn();
      await ws[role].ask("configure", { role });
    }
    const sig = {};
    for (const role of ["A", "B", "C"]) sig[role] = [await count(ws[role], EMAIL), await count(ws[role], IP)];
    signatures.add(JSON.stringify(sig));
    for (const role of order) await ws[role].worker.terminate();
  }
  record("orders.distinctSignatures", signatures.size);
  assert.equal(signatures.size, 1);

  for (const x of [w.A, w.C, fresh, fresh2]) await x.worker.terminate();
  console.log("PASS node probe");
}
