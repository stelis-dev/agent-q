import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  withTransferredPayload,
} from "../dist/payload-delivery-internal.js";

class TestPayloadDeliveryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TestPayloadDeliveryError";
    this.code = code;
  }
}

test("payload transfer helper uploads chunks and consumes a finalized payload ref", async () => {
  const payload = makePayload(5000);
  const digest = sha256Digest(payload);
  const requests = [];
  const chunks = [];
  let receivedBytes = 0;
  const result = await runTransfer(payload, {
    executor: async (request, assertResponse) => {
      requests.push(request);
      if (request.type === "payload_transfer" && request.action === "begin") {
        assert.equal(request.totalBytes, String(payload.length));
        assert.equal(request.payloadDigest, digest);
        return assertResponse(beginResponse(request, "transfer_success"));
      }
      if (request.type === "payload_transfer" && request.action === "chunk") {
        assert.equal(request.offsetBytes, String(receivedBytes));
        const chunk = Buffer.from(request.chunk, "base64");
        chunks.push(chunk);
        receivedBytes += chunk.length;
        return assertResponse(chunkResponse(request, receivedBytes));
      }
      if (request.type === "payload_transfer" && request.action === "finish") {
        return assertResponse(finishResponse(request, "payload_success"));
      }
      throw new Error(`unexpected ${request.type}:${request.action}`);
    },
  });
  assert.equal(result.payloadRef, "payload_success");
  assert.equal(requests.at(-1).action, "finish");
  assert.deepEqual(Buffer.concat(chunks), Buffer.from(payload));
});

test("payload transfer helper rejects payloads over the transfer capacity before upload", async () => {
  const payload = makePayload(3);
  let requestCount = 0;
  await assert.rejects(
    () =>
      runTransfer(payload, {
        payloadMaxBytes: 2,
        executor: async (request, assertResponse) => {
          requestCount += 1;
          return assertResponse({ type: request.type });
        },
      }),
    { code: "payload_too_large" },
  );
  assert.equal(requestCount, 0);
});

test("payload transfer helper aborts an active transfer when begin progress is non-zero", async () => {
  const payload = makePayload(8);
  const seen = [];
  await assert.rejects(
    () =>
      runTransfer(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_transfer" && request.action === "begin") {
            return assertResponse({
              id: request.id,
              version: 1,
              success: true,
              result: {
                transferId: "transfer_begin_progress",
                receivedBytes: "1",
                chunkMaxBytes: "2048",
              },
            });
          }
          if (request.type === "payload_transfer" && request.action === "abort") {
            assert.equal(request.transferId, "transfer_begin_progress");
            return assertResponse(abortResponse(request));
          }
          throw new Error(`unexpected ${request.type}:${request.action}`);
        },
      }),
    { code: "invalid_response" },
  );
  assert.deepEqual(seen.map((request) => request.action), ["begin", "abort"]);
});

test("payload transfer helper aborts an active transfer after chunk progress mismatch", async () => {
  const payload = makePayload(4096);
  const seen = [];
  await assert.rejects(
    () =>
      runTransfer(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_transfer" && request.action === "begin") {
            return assertResponse(beginResponse(request, "transfer_progress_mismatch"));
          }
          if (request.type === "payload_transfer" && request.action === "chunk") {
            return assertResponse(chunkResponse(request, 1));
          }
          if (request.type === "payload_transfer" && request.action === "abort") {
            assert.equal(request.transferId, "transfer_progress_mismatch");
            return assertResponse(abortResponse(request));
          }
          throw new Error(`unexpected ${request.type}:${request.action}`);
        },
      }),
    { code: "invalid_response" },
  );
  assert.equal(seen.at(-1).action, "abort");
});

test("payload transfer helper aborts a finalized payload after consumer failure without replacing the error", async () => {
  const payload = makePayload(8);
  const original = new TestPayloadDeliveryError("consumer_failed", "consumer failed");
  const seen = [];
  let abortSucceeded = false;
  await assert.rejects(
    () =>
      runTransfer(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_transfer" && request.action === "begin") {
            return assertResponse(beginResponse(request, "transfer_consumer_failure"));
          }
          if (request.type === "payload_transfer" && request.action === "chunk") {
            return assertResponse(chunkResponse(request, payload.length));
          }
          if (request.type === "payload_transfer" && request.action === "finish") {
            return assertResponse(finishResponse(request, "payload_consumer_failure"));
          }
          if (request.type === "payload_transfer" && request.action === "abort") {
            assert.equal(request.payloadRef, "payload_consumer_failure");
            abortSucceeded = true;
            return assertResponse(abortResponse(request));
          }
          throw new Error(`unexpected ${request.type}:${request.action}`);
        },
        consume: async () => {
          throw original;
        },
      }),
    (error) => error === original,
  );
  assert.equal(seen.at(-1).action, "abort");
  assert.equal(abortSucceeded, true);
});

test("payload transfer helper reports abort invalid_session on the original error", async () => {
  const payload = makePayload(8);
  let invalidated = false;
  await assert.rejects(
    () =>
      runTransfer(payload, {
        onAbortInvalidSession: () => {
          invalidated = true;
        },
        executor: async (request, assertResponse) => {
          if (request.type === "payload_transfer" && request.action === "begin") {
            return assertResponse(beginResponse(request, "transfer_invalid_session"));
          }
          if (request.type === "payload_transfer" && request.action === "chunk") {
            return assertResponse(chunkResponse(request, 1));
          }
          if (request.type === "payload_transfer" && request.action === "abort") {
            return assertResponse({
              id: request.id,
              version: 1,
              success: false,
              error: {
                code: "invalid_session",
                message: "Session expired.",
                retryable: false,
              },
            });
          }
          throw new Error(`unexpected ${request.type}:${request.action}`);
        },
      }),
    { code: "invalid_response" },
  );
  assert.equal(invalidated, true);
});

test("payload transfer helper freezes payload bytes at call start", async () => {
  const payload = makePayload(4096);
  const original = Buffer.from(payload);
  const uploadedChunks = [];
  await runTransfer(payload, {
    digestPayload: async (bytes) => {
      payload.fill(0xff);
      return sha256Digest(bytes);
    },
    executor: async (request, assertResponse) => {
      if (request.type === "payload_transfer" && request.action === "begin") {
        return assertResponse(beginResponse(request, "transfer_frozen_bytes"));
      }
      if (request.type === "payload_transfer" && request.action === "chunk") {
        uploadedChunks.push(Buffer.from(request.chunk, "base64"));
        return assertResponse(chunkResponse(request, Buffer.concat(uploadedChunks).length));
      }
      if (request.type === "payload_transfer" && request.action === "finish") {
        return assertResponse(finishResponse(request, "payload_frozen_bytes"));
      }
      throw new Error(`unexpected ${request.type}:${request.action}`);
    },
  });
  assert.deepEqual(Buffer.concat(uploadedChunks), original);
});

function runTransfer(payload, options = {}) {
  const digestPayload = options.digestPayload ?? ((bytes) => sha256Digest(bytes));
  return withTransferredPayload({
    sessionId: "session_abcdef",
    payloadBytes: payload,
    chunkMaxBytes: 2048,
    payloadMaxBytes: options.payloadMaxBytes ?? 131072,
    executeTransferRequest: options.executor,
    digestPayload,
    encodeChunkBase64: (chunk) => Buffer.from(chunk).toString("base64"),
    makeError: (code, message) => new TestPayloadDeliveryError(code, message),
    errorCode: (error) => error?.code ?? null,
    onAbortInvalidSession: options.onAbortInvalidSession,
    consumeFinalizedPayload: options.consume ?? (async (payloadRef) => ({ payloadRef })),
  });
}

function beginResponse(request, transferId) {
  return {
    id: request.id,
    version: 1,
    success: true,
    result: {
      transferId,
      receivedBytes: "0",
      chunkMaxBytes: "2048",
    },
  };
}

function chunkResponse(request, receivedBytes) {
  return {
    id: request.id,
    version: 1,
    success: true,
    result: {
      receivedBytes: String(receivedBytes),
    },
  };
}

function finishResponse(request, payloadRef) {
  return {
    id: request.id,
    version: 1,
    success: true,
    result: {
      payloadRef,
    },
  };
}

function abortResponse(request) {
  return {
    id: request.id,
    version: 1,
    success: true,
    result: {},
  };
}

function makePayload(length) {
  const payload = new Uint8Array(length);
  for (let index = 0; index < payload.length; index += 1) {
    payload[index] = (index * 17 + 31) & 0xff;
  }
  return payload;
}

function sha256Digest(payload) {
  return `sha256:${createHash("sha256").update(payload).digest("hex")}`;
}
