interface DigestCrypto {
  readonly subtle?: {
    digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer>;
  };
}

export function getManifestDigest(): ((bytes: Uint8Array) => Promise<string>) | undefined {
  const subtle = (globalThis as { crypto?: DigestCrypto }).crypto?.subtle;
  // Preserve the existing compatibility behavior for hosts without Web Crypto.
  if (subtle === undefined) return undefined;
  return async (bytes) => {
    const hash = new Uint8Array(await subtle.digest("SHA-256", bytes));
    return Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  };
}
