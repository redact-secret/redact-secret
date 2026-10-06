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
