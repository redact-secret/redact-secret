import { createRequire } from "node:module";

function sha256(bytes: Uint8Array): string {
  // Keep loading and hashing inside verification, including their startup cost.
  const { createHash } = createRequire(import.meta.url)("node:crypto") as typeof import("node:crypto");
  return createHash("sha256").update(bytes).digest("hex");
}

export function getManifestDigest(): (bytes: Uint8Array) => string {
  return sha256;
}
