# Redact Secret 0.1.0-beta.3

Adds SendGrid token detection and fixes contextual reference, placeholder, and line-boundary handling.

- Existing tag: `v0.1.0-beta.3`; source: `34ea9b92ed8879082e99f56f8f4715ee4e4f1f35`.
- Mark this GitHub Release as a prerelease. Publication was recovered after an
  initial partial failure; [release status](https://github.com/redact-secret/redact-secret/blob/main/docs/releases/status.md)
  records the evidence and limitations.
- Available: eight npm packages, both Rust crates, and the Python distribution
  (`0.1.0b3`). CLI binaries are not attached by this closeout.
- Install JavaScript with `npm install @redact-secret/core@0.1.0-beta.3`;
  Python with `python -m pip install redact-secret==0.1.0b3`.
- [Versioned changelog](https://github.com/redact-secret/redact-secret/blob/v0.1.0-beta.3/CHANGELOG.md)
  describes the released behavior. Synthetic tests do not establish universal
  secret detection or superiority over other scanners.

Beta APIs and detection limits remain subject to change. Security fixes target
the latest beta, without a backport or fixed-response-time commitment.
