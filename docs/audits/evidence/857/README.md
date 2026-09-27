# Benchmark evidence for #857

[Pinned benchmark evidence](https://github.com/redact-secret/redact-secret-benchmarks/blob/a66dbef943ccbb9fd4ffd6747e0ddaf7914c10a0/evidence/857/README.md)

**Result:** PARTIAL PASS on the frozen candidate. Connection-string passwords, OTP seeds, and bounded assignment literals pass every `credential-policy-v1` gate and classify as `Stable · Policy qualified`; Bearer credentials remain provisional because the single-use protected holdout recorded one unresolved failure. All four remain `T3` with `evidenceBasis: project-policy`.
