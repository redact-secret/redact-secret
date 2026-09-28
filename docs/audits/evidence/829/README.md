# Benchmark evidence for #829

[Pinned benchmark evidence](https://github.com/redact-secret/redact-secret-benchmarks/blob/3647c8cd30a645754135650b36af80e26b1d65bb/evidence/829/README.md)

**Result:** all four invariants hold over 2,762 deterministic variants in 9 attack classes (0 unresolved, 0 unstable) against `evidence-aggregation/v3`, the model whose randomness group reads the residual entropy instead of Shannon entropy. Under the projected promotion (flag a statistical finding at shadow band `medium` or above), 171 resolved positives would leak that the legacy path flags. Future-promotion Q4 reads **fail**. The failure is structural to the calibrated operating point, not to the randomness measure: randomness alone stays below `low` and context alone reaches `medium`, so no randomness signal changes an outcome read at `medium`. The model is **not promotable**, and it stays shadow-only and non-enforcing.
