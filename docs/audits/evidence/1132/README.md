# Stream the exact JWT anon exception check without payload heap copies (#1132)

Parent: #1068. Verdict: **adopted**. Behavior-preserving internal change in
`crates/secret-scan-core/src/detectors/jwt.rs`; no finding, span, type,
confidence, order, ID, or public API changes.

## What changed

`is_supabase_legacy_anon_claim()` used to decode the whole payload segment
into a `Vec`, validate the whole decoded text as UTF-8, then search two exact
literals. It now decodes into a fixed 2,048-byte stack buffer, validates
UTF-8 per flush (holding back an incomplete trailing sequence), keeps 15
bytes of decoded text (longest marker minus one) across flushes so a marker
split by a flush is still found, and validates to the end of the payload even
after both markers are found. Invalid alphabet, a one-sextet remainder, and
invalid UTF-8 anywhere still return `false` (structural detection stands).
The old implementation is kept under `#[cfg(test)]` as the oracle. Decoded
bytes still pass through a stack buffer, so this is not a secure-erasure
claim. No global or reusable plaintext pool, no new dependency, no `unsafe`.

## Exactness evidence (deterministic)

Differential tests in `detectors::jwt::tests` compare the new function with
the oracle on synthetic payloads only:

- both markers at 4 filler widths (1 to 4 byte scalars), 40 leading offsets,
  19 gaps straddling the 2,048-byte buffer, plus reversed order and a single
  marker;
- 7 invalid or truncated UTF-8 tails placed trailing, inner, and after both
  markers at 17 pad lengths around 2,048 and 4,096;
- every prefix length (all remainders, including the one-sextet case), and an
  invalid alphabet byte (`= + / . space 0xFF`) at every index, plus one at the
  end of a 5,000-byte payload;
- 4,000 xorshift-generated payloads mixing markers, `service_role`, 3 and 4
  byte scalars and invalid bytes.

The decoded-payload heap allocation is gone by construction: no allocating
call remains in the function (the #1068 meter measured 2 calls to 0 for the
prototype of this design).

## Timing (exploratory, loaded host)

`cargo test --release` ignored temporary test, median of 7 rounds,
black-boxed, nanoseconds per call, on a loaded shared macOS host. This is a
helper micro-measurement, not a full-scan claim; the helper only runs on a
JWT shape match, so whole-scan cost on non-JWT text is unchanged.

| Workload | Oracle ns | Streaming ns |
|---|---|---|
| short anon (52 B payload) | 107.1 | 79.9 |
| short non-anon (63 B) | 159.7 | 84.4 |
| long anon (80,052 B) | 40,695 | 37,303 |
| long non-anon (80,063 B) | 50,140 | 41,297 |

A first version (512-byte buffer, per-byte alphabet `match`) was 40 to 50%
slower on long payloads than the oracle (66,737 vs 44,623 ns); a 256-entry
const sextet table and a larger buffer removed that regression. The
temporary measurement test was not committed.

## Cost and boundaries

- Stack: one 2,048-byte buffer, live only inside the helper. No recursion.
- Not measured here: WASM stack size and cross-runtime release
  qualification, which belong to the #1068 qualification pass and
  `redact-secret-benchmarks`.
- Not done by design: whitespace, escaped-key or JSON exceptions;
  `service_role` is not exempted.
