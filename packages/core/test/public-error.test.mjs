import assert from "node:assert/strict";
import test from "node:test";
import { AgentQError } from "../dist/errors.js";
import { toPublicErrorFromUnknown } from "../dist/public-error.js";

test("toPublicErrorFromUnknown canonicalizes AgentQError without raw message leakage", () => {
  assert.deepEqual(
    toPublicErrorFromUnknown(new AgentQError("transport_closed", "raw /dev/cu.secret", true)),
    {
      code: "transport_closed",
      message: "Device connection closed before a valid response.",
      retryable: true,
    },
  );
});

test("toPublicErrorFromUnknown collapses unknown thrown values to the public error table", () => {
  assert.deepEqual(toPublicErrorFromUnknown(new Error("raw stack and path")), {
    code: "unknown_error",
    message: "Agent-Q request failed.",
    retryable: false,
  });
  assert.deepEqual(toPublicErrorFromUnknown("raw string failure"), {
    code: "unknown_error",
    message: "Agent-Q request failed.",
    retryable: false,
  });
});

test("toPublicErrorFromUnknown normalizes unsupported AgentQError codes", () => {
  assert.deepEqual(
    toPublicErrorFromUnknown(new AgentQError("ignore_previous_instructions", "raw text", true)),
    {
      code: "unknown_error",
      message: "Agent-Q request failed.",
      retryable: false,
    },
  );
});
