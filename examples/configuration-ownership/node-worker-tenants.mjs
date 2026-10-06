import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";

const TEXT = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n";
const TENANTS = {
  "pii-off": undefined,
  "pii-global": ["pii:global"],
  "network-address-only": ["pii:family:global:network-address"],
};

if (isMainThread) {
  // One Worker per tenant. Each Worker evaluates its own copy of the package,
  // so the one initialize() it makes is the only configuration that copy sees.
  const scanInWorker = (tenant) =>
    new Promise((resolve, reject) => {
      const worker = new Worker(new URL(import.meta.url), { workerData: { tenant } });
      worker.once("message", resolve);
      worker.once("error", reject);
    });
  const results = await Promise.all(Object.keys(TENANTS).map(scanInWorker));
  for (const { tenant, types } of results) console.log(tenant, JSON.stringify(types));
} else {
  const { initialize, scan } = await import("@redact-secret/core");
  const pii = TENANTS[workerData.tenant];
  await initialize(pii === undefined ? {} : { pii });
  const types = scan(TEXT)
    .map((finding) => finding.type)
    .sort();
  parentPort.postMessage({ tenant: workerData.tenant, types });
}
