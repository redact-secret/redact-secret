import { initialize, piiActivation } from "@redact-secret/core";

// Within one thread there is one runtime per entry point. A second selection
// does not create a second owner; it conflicts with the first.
await initialize({ pii: ["pii:global"] });
await initialize({ pii: ["pii", "pii:global"] }); // equivalent selection: idempotent
try {
  await initialize({ pii: ["pii:family:global:network-address"] });
} catch (error) {
  console.log(error.code);
}
console.log(piiActivation().includes("selectors=pii:global;"));
