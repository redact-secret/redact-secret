import assert from "node:assert/strict";
import test from "node:test";

import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";
import { RedactingSpanProcessorWith, redactAttributesWith } from "./redact-span-attributes.mjs";

function fakeNextProcessor(exported) {
  return {
    started: [],
    onStart(span, parentContext) {
      this.started.push({ span, parentContext });
    },
    onEnd(span) {
      exported.push(span);
    },
    shutdown() {
      return Promise.resolve("shutdown");
    },
    forceFlush() {
      return Promise.resolve("flushed");
    },
  };
}

test("redacts string and string-array span and event attributes; no plaintext reaches the exporter", () => {
  const exported = [];
  const processor = new RedactingSpanProcessorWith(fakeNextProcessor(exported), fakeScanAndRedact);

  const span = {
    attributes: {
      "llm.input_messages": "call SECRET_TOKEN_1 now",
      "llm.tags": ["ok", "BLOCK_ME here"],
      "retry.count": 3,
      "retry.ok": true,
    },
    events: [{ name: "tool_call", attributes: { "tool.args": "value SECRET_TOKEN_2 done" } }],
  };

  processor.onEnd(span);

  assert.equal(exported.length, 1);
  assert.equal(exported[0].attributes["llm.input_messages"], "call <SECRET_1> now");
  assert.deepEqual(exported[0].attributes["llm.tags"], ["ok", "[REDACTED:BLOCKED]"]);
  assert.equal(exported[0].attributes["retry.count"], 3);
  assert.equal(exported[0].attributes["retry.ok"], true);
  assert.equal(exported[0].events[0].attributes["tool.args"], "value <SECRET_1> done");

  const serialized = JSON.stringify(exported);
  assert.equal(serialized.includes("SECRET_TOKEN_1"), false);
  assert.equal(serialized.includes("SECRET_TOKEN_2"), false);
  assert.equal(serialized.includes("BLOCK_ME"), false);
});

test("a core failure on one attribute fails closed without throwing into the SDK", () => {
  const exported = [];
  const processor = new RedactingSpanProcessorWith(fakeNextProcessor(exported), fakeScanAndRedact);
  const span = { attributes: { boom: "trigger BOOM here" }, events: [] };

  processor.onEnd(span);

  assert.equal(exported[0].attributes.boom, "[REDACTED:ERROR]");
  assert.equal(JSON.stringify(exported).includes("BOOM"), false);
});

test("onStart, shutdown, and forceFlush delegate to the wrapped processor", async () => {
  const next = fakeNextProcessor([]);
  const processor = new RedactingSpanProcessorWith(next, fakeScanAndRedact);

  processor.onStart("span-1", "ctx-1");
  assert.deepEqual(next.started, [{ span: "span-1", parentContext: "ctx-1" }]);
  assert.equal(await processor.shutdown(), "shutdown");
  assert.equal(await processor.forceFlush(), "flushed");
});

test("redactAttributesWith is a no-op for undefined or null attributes", () => {
  assert.doesNotThrow(() => redactAttributesWith(fakeScanAndRedact, undefined));
  assert.doesNotThrow(() => redactAttributesWith(fakeScanAndRedact, null));
});

test("rejects a next processor without onEnd, or a non-function scanAndRedact", () => {
  assert.throws(() => new RedactingSpanProcessorWith({}, fakeScanAndRedact), TypeError);
  assert.throws(() => new RedactingSpanProcessorWith(fakeNextProcessor([]), null), TypeError);
});
