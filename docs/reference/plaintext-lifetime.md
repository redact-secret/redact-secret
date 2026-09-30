# Plaintext memory lifetime

[Documentation home](../README.md)

This page says what Redact Secret promises about input text that sits in
process memory while it scans, and what it does not. It is a memory-lifetime
contract, separate from the output-safety contract (findings and errors never
carry matched text, see [Threat model](../specs/threat-model.md)). It is
decided by
[`decision-define-the-plaintext-memory-lifetime-contract`](../decisions/2026-09-30-define-the-plaintext-memory-lifetime-contract.md)
and the code-path inventory behind every statement here is
[#1079 evidence](../audits/evidence/1079/README.md), which carries the file and
line for each buffer.

## The contract in one paragraph

Redact Secret minimizes owned copies of plaintext and bounds how long an
incremental session retains it. Findings, errors and `Debug` output do not
carry matched text. When a session ends, by `finalize`, `abort` or any failure,
it no longer owns any input-derived text. The core does **not** claim that
ordinary `drop` or deallocation erases memory: released buffers go back to the
allocator with their bytes intact. It does not zero caller-owned input, the
sanitized output it returns, or any copy a host runtime, binding, allocator,
operating system or CPU makes. No build of the core currently overwrites any
buffer, so nothing on this page describes zeroization. If an opt-in
zeroization mode is added ([#1080](https://github.com/redact-secret/redact-secret/issues/1080)),
this page will name the exact buffers and build mode it covers and keep every
limit below.

## Words this page uses

| Word | Means |
| --- | --- |
| **Borrowed** | The core reads the caller's `&str`. The caller owns the memory and its lifetime. |
| **Owned** | The core allocated a `String` or `Vec` holding input-derived text. |
| **Released** (or **discarded**) | The core dropped its owner, so the allocation returned to the allocator. The bytes are not overwritten. |
| **Zeroized** | The bytes were explicitly overwritten by a write the optimizer cannot remove. Nothing in the core does this today. |

The two words are never interchangeable. Rust's own `Vec` documentation says
removed or dropped data is not guaranteed to be erased, and that a plain
overwrite may be optimized away.

## Where plaintext can exist

Summary of the [inventory](../audits/evidence/1079/README.md). IDs match it.

| Path | Buffer | Who owns it | Released |
| --- | --- | --- | --- |
| Whole-input `scan`, `redact`, `scanAndRedact` | The input (W1) | Caller | By the caller |
| | A normalized scan copy (W2), only when the input has governed invisible code points | The call | When the scan returns or fails |
| | Detector temporaries (D1 to D11): short-lived lowercased or normalized copies of a value, a line or a context window | The detector call | When that detector returns |
| | Sanitized output (W9) | Moved to the caller | By the caller |
| `IncrementalSanitizer` | `retained` (I2): unresolved text, closed units waiting in a batch, and the current unit | The session | After each flush, by replacement with only the open tail; on `finalize`, `abort`, failure |
| | A normalized `scanned` copy of the current unit (I3), only after a piece loses an invisible code point | The session | With the unit, and on every terminal transition |
| | A lead (I5): a copy of an already-released line carrying an AWS access key ID, kept so the next unit can read it | The session | At the next flush that no longer needs it, and on every terminal transition |
| | The private-key tracker's `lookbehind` (I7): at most a delimiter-length suffix of a piece | The session | At unit end and on every terminal transition |
| | Sanitized output of a call (I11) | Moved to the caller | By the caller |
| Bindings and CLI | Host copies of the input and of the result | The host | By the host |

No `static`, `thread_local` or cache in the core retains input text. The
thread-local scan marker holds an address, a length and lossy summaries, and is
restored when the scan ends.

## What the core guarantees

1. **Output safety.** A `Finding`, a `SecretScanError`, and the `Debug` output
   of a finding or session carry no matched text. A placeholder that would
   reproduce any finding's matched value is rejected.
2. **No side effects.** The core makes no network call, writes no file, reads no
   environment and stores no secret. Input text leaves it only through the
   values it returns.
3. **Bounded whole-input copying.** A whole-input scan makes at most one
   input-sized owned copy (the normalized copy), only for input that loses an
   invisible code point, allocated once at its final size and dropped before
   the call returns. Redaction allocates its output once at the final size.
   Matched text is not copied for placeholder checking (#1076).
4. **Bounded incremental retention.** A session holds only text that cannot yet
   be resolved, inside the four limits the caller declares. A line released
   in output is not held back, except the one-line lead in I5.
5. **Terminal release.** After `finalize`, after `abort`, and after any
   failure (input, buffer, token or multiline limit; detector, policy,
   formatter or placeholder failure), the session owns no input-derived text
   and no parser state derived from it. Every later call returns
   `INVALID_STATE`. Structural tests check this for each transition.
6. **Action-aware output.** `redact` and `block` findings are replaced in the
   output. `warn` and `allow` findings are not: the output deliberately still
   holds that text. "Sanitized" means only that replaced spans are replaced.
7. **No unsafe code** in the core (`#![forbid(unsafe_code)]`), so no hidden
   aliasing of these buffers.

## What the core does not guarantee

1. **Erasure.** Releasing a buffer does not clear it. A dropped `String` leaves
   its bytes in freed memory until the allocator reuses the block.
2. **Historical copies.** An owned buffer that grows by appending reallocates,
   and each earlier allocation is freed un-cleared. Today `retained` and
   `scanned` grow this way. After every flush the session also replaces
   `retained` with a fresh copy of the open tail, which frees the allocation
   that held every released unit, matched values included. "Released on a
   terminal transition" therefore covers the current allocation only.
3. **Caller-owned memory.** The input you pass, and the output text you
   receive, are yours. That output can contain the original value under `warn`
   and `allow`, and the core cannot shorten its life.
4. **Everything a host makes.** See the next section.
5. **Registers, stack, allocator and OS.** Stack frames and spilled registers
   during a scan, the allocator's free lists and reuse, swap, hibernation
   files, core and crash dumps, debugger or RAM acquisition, and
   microarchitectural leakage. The core does not try to address these.
6. **Extensions.** A custom detector, policy or formatter is in-process trusted
   code. The core passes callbacks metadata, never matched text, but cannot
   control what a callback or a detector keeps.
7. **Abnormal exit.** Dropping an `accepting` session, or a panic that unwinds
   through one, enters no terminal state. The buffers are freed when the
   session drops, un-cleared, and there is no guard that aborts on unwind.
8. **Timing.** Retention lasts until the next closing boundary or terminal
   call, not for a fixed time. A session you never finish holds its tail until
   it is dropped.

## By runtime

Guarantees 1 to 7 above are properties of the Rust core and hold in every
runtime. The rows below add what each host changes. They are not
interchangeable, and a statement about one does not carry to another.

| Runtime | What the host adds | What is not promised |
| --- | --- | --- |
| **Native Rust** (`redact-secret` crate) | `&str` in, owned `String` out. The copies are the ones in the table above and nothing else. | Erasure on drop. Zeroization of the allocation, of earlier reallocations, or of your input and output. |
| **CLI** | Whole-file mode reads the file into a `Vec<u8>` that grows by doubling, then the `String` it becomes; stream mode copies each chunk into an owned buffer before `append`. A failed read, decode or write aborts the session. | Erasure of the read buffer, the file or chunk copies, or the terminal scrollback and pipes the output reaches. |
| **Node.js** (N-API addon) | The JS string is converted to an owned Rust `String` for each call, freed when the call returns. The result text is copied into a new JS string. | Anything in V8: JS strings are immutable, may be interned and cannot be wiped. The Rust copy is freed un-cleared. |
| **WebAssembly** (browser, Workers, Node fallback) | Arguments are encoded into the module's linear memory, and results are decoded back out. Linear memory never shrinks, and any JS code holding the module's `memory` can read all of it, including freed blocks, for the life of the instance. Whole-input results move out through `takeText` and `free()` (#1077); incremental results currently clone text in linear memory and rely on handle cleanup by the host. | Any erasure. The sandbox isolates the module from other code, not one buffer from another, and does not clear freed memory. A discarded session's freed bytes stay in linear memory until reused. |
| **Python** (PyO3 extension) | Input is borrowed from the `str`; CPython may cache a UTF-8 copy of a non-ASCII `str` inside that object. The result text becomes one `str` and the Rust `String` is dropped (#1077). `with` and a host append failure abort the session. | Erasure of any `str`: CPython strings are immutable and freed without clearing. |

## Out of scope

These are outside what the core can address, and nothing here promises them:
CPU registers and stack spills, allocator history and reuse, swap and
hibernation, core and crash dumps, debugger and RAM scraping,
microarchitectural side channels (Spectre-class), copies made by callers,
bindings, runtimes, loggers, APM agents and terminals, and protected-memory
mechanisms (`mlock`, `mprotect`, enclaves). Scanning needs the plaintext, so
it cannot be equivalent to protected-memory secret storage.

## What to do with it

- Scan as early as the data reaches your process, and drop your reference to the
  original when you have the sanitized text.
- Always finish a session: call `abort` (or use Python's `with`) on every path
  that does not reach `finalize`, including exceptions. Do not rely on drop.
- Keep the four incremental limits at the narrowest values your workload needs:
  they bound how much a session holds.
- Keep chunk sizes bounded. The limits do not cap a binding's own per-chunk
  copies.
- If your threat model includes someone reading process memory, swap or dumps,
  isolate the work in a short-lived process and disable dumps and swap for it.
  This library does not provide that.
- Treat `warn` and `allow` output as still carrying the value.

## Changing this page

A change that adds an owned copy of input-derived text to the core states why
the copy is needed in its pull request and updates the inventory, or removes
the copy instead. A claim that any buffer is zeroized needs the mechanism, the
build mode, the exact buffers and a test for each terminal state first.
