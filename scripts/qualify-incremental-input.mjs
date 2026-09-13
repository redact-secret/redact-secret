/** Shared host-validation lifecycle regression for real Node and Wasm artifacts. */
export function qualifyIncrementalInput(createIncrementalSanitizer, SecretScanError) {
  function assert(condition, message) {
    if (!condition) throw new Error(message);
  }
  function rejects(operation, code, message) {
    let thrown;
    try {
      operation();
    } catch (error) {
      thrown = error;
    }
    assert(thrown instanceof SecretScanError, "invalid input lifecycle: expected a public error");
    assert(thrown.code === code, "invalid input lifecycle: incorrect error code");
    assert(thrown.message === message, "invalid input lifecycle: incorrect fixed message");
    assert(thrown.cause === undefined, "invalid input lifecycle: unexpected error cause");
  }
  for (const [chunk, code, message] of [
    [42, "INVALID_INPUT", "Secret scan input must be a string."],
    [null, "INVALID_INPUT", "Secret scan input must be a string."],
    ["\uD800", "UNPAIRED_SURROGATE", "Secret scan input contains an unpaired UTF-16 surrogate."],
    ["\uDC00", "UNPAIRED_SURROGATE", "Secret scan input contains an unpaired UTF-16 surrogate."],
  ]) {
    const session = createIncrementalSanitizer({
      limits: {
        maxInputCodeUnits: 256,
        maxBufferedCodeUnits: 192,
        maxTokenCodeUnits: 64,
        maxMultilineCodeUnits: 64,
      },
    });
    // No closing boundary: the core retains text and the binding indexes Unicode.
    const retained = session.append("🔑SYNTHETIC_REVOKED_RETAINED_TEXT");
    assert(retained.text === "" && retained.findings.length === 0,
      "invalid input lifecycle: prefix was not retained");
    rejects(() => session.append(chunk), code, message);
    assert(session.state === "failed", "invalid input lifecycle: rejection was not failed");
    for (const operation of [
      () => session.append("x"), () => session.append(chunk),
      () => session.finalize(), () => session.abort(),
    ]) {
      rejects(operation, "INVALID_STATE", "The incremental sanitizer is no longer accepting input.");
      assert(session.state === "failed", "invalid input lifecycle: terminal state changed");
    }
  }
}
