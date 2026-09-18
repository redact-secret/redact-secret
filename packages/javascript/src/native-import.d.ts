/**
 * Ambient declarations for the `#native` and `#native-common` subpath
 * imports.
 *
 * The package's `imports` map resolves `#native` to `dist/runtime/node.js`
 * under the `node` condition and to `dist/runtime/browser.js` under `browser`
 * (and by default), so a browser build never reaches the Node addon or a
 * `node:` module. `#native-common` selects `node-common.js` or
 * `browser-common.js` the same way. Declaring the specifier here keeps that selection a runtime
 * concern: the compiler sees one contract instead of one of the two
 * implementations.
 */
declare module "#native" {
  export const loadNativeBinding: import("./native.js").NativeBindingLoader;
}

declare module "#native-common" {
  export const loadNativeBinding: import("./native.js").NativeBindingLoader;
}
