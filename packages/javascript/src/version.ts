/**
 * The shared product version.
 *
 * The Rust crate, the npm package, the Python package, and the CLI carry one
 * SemVer version per release (`decision-release-bindings-in-lockstep`), so
 * `initialize()` refuses a binding artifact that reports a different one.
 */
export const VERSION = "0.1.0-beta.5";
