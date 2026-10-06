// Same-process isolation probe for the WebAssembly artifacts (issue #1221).
//
//   node scripts/build-browser-artifact.mjs --out-dir <dir>/wasm-full
//   node scripts/build-browser-artifact.mjs --detector-profile common --out-dir <dir>/wasm-common
//   node docs/audits/evidence/1221/probe-wasm.mjs <dir>
//
// A WebAssembly module instance owns its memory and its thread-local cells, so
// instantiating the same glue under a distinct module URL yields an
// independent configuration owner. `@redact-secret/core` does not do this: its
// runtime binds one instance per entry profile. This probe uses the generated
// glue directly, so it demonstrates what the artifact allows, not what the
// facade exposes. Every value is synthetic and assembled at run time.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const dir = process.argv[2];
const EMAIL = "email: owner.synthetic@mail-synthetic.org";
const IP = "client_ip = 192.168.1.7";
const TOKEN_LINE = `API_KEY=${["ghp", "_SYNTHETICREVOKED", "0".repeat(20)].join("")}`;
const R1 = Buffer.from(
  'ruleset-revision: 1\ndetector: acme-one\nspecificity: contextual\nprefix: "ACMEONE_"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n',
);
const R1_TEXT = `v = ACMEONE_${"abcdefghij".repeat(3)}`;
const record = (name, value) => console.log(`${name}: ${JSON.stringify(value)}`);

async function instance(profile, pii, tag) {
  const base = profile === "full" ? "redact_secret_wasm" : "redact_secret_wasm_common";
  const stem = pii ? `${base}_pii` : base;
  const folder = join(dir, profile === "full" ? "wasm-full" : "wasm-common");
  const glue = await import(`${pathToFileURL(join(folder, `${stem}.js`)).href}?instance=${tag}`);
  glue.initSync({ module: readFileSync(join(folder, `${stem}_bg.wasm`)) });
  return glue;
}
const types = (findings) => findings.map((f) => f.type).sort();
const code = (fn) => {
  try {
    return { ok: fn() };
  } catch (e) {
    return { err: e?.code ?? String(e?.message ?? e).slice(0, 60) };
  }
};

// 1. A (PII off, default artifact), B (pii:global) and C (network-address) coexist.
const A = await instance("full", false, "A");
const B = await instance("full", true, "B");
const C = await instance("full", true, "C");
A.initialize([]);
B.initialize(["pii:global"]);
C.initialize(["pii:family:global:network-address"]);
const seen = {};
for (const [role, m] of Object.entries({ A, B, C })) {
  seen[role] = {
    email: m.scan(EMAIL).length,
    ip: m.scan(IP).length,
    token: m.scan(TOKEN_LINE).length,
    activation: m.piiActivation().split(";")[1],
  };
}
record("concurrent", seen);
assert.deepEqual([seen.A.email, seen.A.ip], [0, 0]);
assert.ok(seen.B.email > 0 && seen.B.ip > 0);
assert.deepEqual([seen.C.email > 0, seen.C.ip > 0], [false, true]);
assert.ok(seen.A.token > 0 && seen.B.token > 0 && seen.C.token > 0);

// 2. The default artifact refuses PII by construction.
const D = await instance("full", false, "D");
record("defaultArtifact.pii", code(() => D.initialize(["pii:global"])));

// 3. Legacy contract inside one instance: equivalent is idempotent, differing conflicts.
record("legacy", {
  equivalent: code(() => B.initialize(["pii"])),
  differing: code(() => B.initialize(["pii:family:global:network-address"])),
  offAfterOn: code(() => B.initialize([])),
});
assert.ok("ok" in code(() => B.initialize(["pii"])));
assert.ok("err" in code(() => B.initialize([])));

// 4. Streams interleaved across the three instances; the email splits at a chunk boundary.
const sessions = Object.fromEntries(
  Object.entries({ A, B, C }).map(([role, m]) => [role, m.createIncrementalSanitizer(32768, 16512, 8192, 16384)]),
);
const half = EMAIL.indexOf("@") + 3;
const streamTypes = { A: [], B: [], C: [] };
for (const chunk of [EMAIL.slice(0, half), EMAIL.slice(half), `\n${IP}\n`]) {
  for (const role of ["A", "B", "C"]) streamTypes[role].push(...types(sessions[role].append(chunk).findings));
}
for (const role of ["A", "B", "C"]) streamTypes[role].push(...types(sessions[role].finalize().findings));
record("streams", streamTypes);
assert.equal(streamTypes.A.length, 0);
assert.equal(streamTypes.B.length, 2);
assert.deepEqual(streamTypes.C, ["pii_global_network_address"]);

// 5. Rulesets: each instance has its own one-slot cache; alternating does not cross instances.
const rs = {};
for (const [role, m] of Object.entries({ A, B, C })) {
  const withRuleset = m.scan(R1_TEXT, undefined, undefined, undefined, R1).length;
  const without = m.scan(R1_TEXT).length;
  const piiAlongside = m.scan(EMAIL, undefined, undefined, undefined, R1).length;
  rs[role] = { withRuleset, without, piiAlongside };
}
record("rulesets", rs);
for (const role of ["A", "B", "C"]) assert.ok(rs[role].withRuleset > 0 && rs[role].without === 0);
assert.deepEqual([rs.A.piiAlongside, rs.B.piiAlongside > 0, rs.C.piiAlongside], [0, true, 0]);

// 6. Construction-order permutations, each on fresh instances.
const sigs = new Set();
let n = 0;
for (const order of [["A", "B", "C"], ["C", "B", "A"], ["B", "A", "C"]]) {
  const made = {};
  for (const role of order) {
    const m = await instance("full", role !== "A", `perm${n}${role}`);
    m.initialize(role === "A" ? [] : role === "B" ? ["pii:global"] : ["pii:family:global:network-address"]);
    made[role] = [m.scan(EMAIL).length, m.scan(IP).length];
  }
  sigs.add(JSON.stringify(made, Object.keys(made).sort()));
  n += 1;
}
record("orders.distinct", sigs.size);
assert.equal(sigs.size, 1);

// 7. Profiles: a common instance and a full instance in one process; teardown is dropping the reference.
const common = await instance("common", false, "common");
common.initialize([]);
record("profiles", { full: A.profile(), common: common.profile(), commonSeesProviderToken: common.scan(TOKEN_LINE).length, fullSeesProviderToken: A.scan(TOKEN_LINE).length });
assert.equal(common.profile(), "common");

// 8. Detector disabling and overlap (common drops provider detectors).
const BARE = TOKEN_LINE.slice("API_KEY=".length);
record("bareProviderToken", { full: types(A.scan(BARE)), common: types(common.scan(BARE)), fullKeyed: types(A.scan(TOKEN_LINE)), commonKeyed: types(common.scan(TOKEN_LINE)) });
assert.ok(A.scan(BARE).length > 0 && common.scan(BARE).length === 0);

// 9. An un-initialized instance refuses to scan, and piiActivation is not a free read.
const E = await instance("full", true, "E");
record("uninitialized", { scan: code(() => E.scan(EMAIL)), activation: code(() => E.piiActivation()) });

// Teardown: a re-created instance starts with no inherited selection.
let F = await instance("full", true, "F1");
F.initialize(["pii:global"]);
F = undefined;
const F2 = await instance("full", true, "F2");
record("teardown.recreated", code(() => F2.initialize(["pii:family:global:network-address"])));
assert.ok("ok" in code(() => F2.initialize(["pii:family:global:network-address"])));
console.log("PASS wasm probe");
