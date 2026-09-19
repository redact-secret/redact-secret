/**
 * Ambient declaration for the browser artifact.
 *
 * `@redact-secret/wasm` is the `wasm-bindgen` build published in
 * lockstep with this package (`decision-release-bindings-in-lockstep`); it is
 * generated, so it is absent from a source checkout. Declaring it here keeps
 * the specifier a literal, which is what lets a bundler resolve the glue and
 * the `.wasm` binary it references. `runtime/browser.ts` validates the shape
 * it actually loaded before using it.
 */
declare module "@redact-secret/wasm" {
  const generated: unknown;
  export default generated;
}

/**
 * As above, for the `common`-profile artifact `@redact-secret/wasm` ships
 * under its `common` subpath export (`decision-define-detector-profile-and-pack-contract`).
 * `runtime/browser-common.ts` validates the shape it actually loaded before
 * using it.
 */
declare module "@redact-secret/wasm/common" {
  const generated: unknown;
  export default generated;
}

/**
 * As above, for the raw `.wasm` binaries `runtime/workerd.ts`/
 * `workerd-common.ts` import directly by their own literal specifier
 * (`decision-verify-edge-runtimes`): a bundler that resolves a `workerd`
 * condition compiles a `.wasm`-extension import to a `WebAssembly.Module`
 * rather than fetching it, which is what those loaders pass straight into
 * the generated glue's `default()` instead of relying on its `import.meta.url`
 * fallback (unavailable in `workerd`, verified while implementing this
 * decision).
 */
declare module "@redact-secret/wasm/redact_secret_wasm_bg.wasm" {
  const module: WebAssembly.Module;
  export default module;
}

declare module "@redact-secret/wasm/redact_secret_wasm_common_bg.wasm" {
  const module: WebAssembly.Module;
  export default module;
}
