import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  withUploadedSignablePayload,
} from "../dist/payload-delivery-internal.js";
import {
  SIGNABLE_PAYLOAD_KIND_TRANSACTION,
} from "../dist/protocol.js";

class TestPayloadDeliveryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TestPayloadDeliveryError";
    this.code = code;
  }
}

const capability = {
  kind: "transaction",
  inlineMaxBytes: "384",
  chunkMaxBytes: "2048",
  payloadMaxBytes: "131072",
};

test("payload delivery helper uploads chunks and consumes a finalized descriptor", async () => {
  const payload = makePayload(5000);
  const digest = sha256Digest(payload);
  const requests = [];
  const chunks = [];
  let receivedBytes = 0;
  const result = await runUpload(payload, {
    executor: async (request, assertResponse) => {
      requests.push(request);
      if (request.type === "payload_upload_begin") {
        assert.equal(request.sizeBytes, String(payload.length));
        assert.equal(request.payloadDigest, digest);
        return assertResponse({
          id: request.id,
          version: 1,
          type: "payload_upload_begin_result",
          uploadId: "upload_success",
          receivedBytes: "0",
          chunkMaxBytes: "2048",
        });
      }
      if (request.type === "payload_upload_chunk") {
        assert.equal(request.offsetBytes, String(receivedBytes));
        const chunk = Buffer.from(request.chunk, "base64");
        chunks.push(chunk);
        receivedBytes += chunk.length;
        return assertResponse({
          id: request.id,
          version: 1,
          type: "payload_upload_chunk_result",
          receivedBytes: String(receivedBytes),
        });
      }
      if (request.type === "payload_upload_finish") {
        return assertResponse({
          id: request.id,
          version: 1,
          type: "payload_upload_finish_result",
          payloadRef: "payload_success",
          chain: "sui",
          method: "sign_transaction",
          payloadKind: "transaction",
          sizeBytes: String(payload.length),
          payloadDigest: digest,
        });
      }
      throw new Error(`unexpected ${request.type}`);
    },
  });
  assert.equal(result.payloadRef, "payload_success");
  assert.equal(requests.at(-1).type, "payload_upload_finish");
  assert.deepEqual(Buffer.concat(chunks), Buffer.from(payload));
});

test("payload delivery helper rejects payloads over the capability before upload", async () => {
  const payload = makePayload(3);
  let requestCount = 0;
  await assert.rejects(
    () =>
      runUpload(payload, {
        capabilityOverride: { ...capability, payloadMaxBytes: "2" },
        executor: async (request, assertResponse) => {
          requestCount += 1;
          return assertResponse({ type: request.type });
        },
      }),
    { code: "unsupported_payload_size" },
  );
  assert.equal(requestCount, 0);
});

test("payload delivery helper aborts an active upload when begin progress is non-zero", async () => {
  const payload = makePayload(8);
  const seen = [];
  await assert.rejects(
    () =>
      runUpload(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_upload_begin") {
            return assertResponse({
              id: request.id,
              version: 1,
              type: "payload_upload_begin_result",
              uploadId: "upload_begin_progress",
              receivedBytes: "1",
              chunkMaxBytes: "2048",
            });
          }
          if (request.type === "payload_upload_abort") {
            assert.equal(request.uploadId, "upload_begin_progress");
            return assertResponse({
              id: request.id,
              version: 1,
              type: "payload_upload_abort_result",
              status: "aborted",
            });
          }
          throw new Error(`unexpected ${request.type}`);
        },
      }),
    { code: "protocol_error" },
  );
  assert.deepEqual(seen.map((request) => request.type), ["payload_upload_begin", "payload_upload_abort"]);
});

test("payload delivery helper aborts an active upload after chunk progress mismatch", async () => {
  const payload = makePayload(4096);
  const seen = [];
  await assert.rejects(
    () =>
      runUpload(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_upload_begin") {
            return beginResponse(request, "upload_progress_mismatch");
          }
          if (request.type === "payload_upload_chunk") {
            return assertResponse({
              id: request.id,
              version: 1,
              type: "payload_upload_chunk_result",
              receivedBytes: "1",
            });
          }
          if (request.type === "payload_upload_abort") {
            assert.equal(request.uploadId, "upload_progress_mismatch");
            return abortResponse(request);
          }
          throw new Error(`unexpected ${request.type}`);
        },
      }),
    { code: "protocol_error" },
  );
  assert.equal(seen.at(-1).type, "payload_upload_abort");
});

test("payload delivery helper aborts a finalized payload after descriptor mismatch", async () => {
  const payload = makePayload(8);
  const seen = [];
  await assert.rejects(
    () =>
      runUpload(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_upload_begin") {
            return beginResponse(request, "upload_descriptor_mismatch");
          }
          if (request.type === "payload_upload_chunk") {
            return chunkResponse(request, payload.length);
          }
          if (request.type === "payload_upload_finish") {
            return assertResponse({
              id: request.id,
              version: 1,
              type: "payload_upload_finish_result",
              payloadRef: "payload_descriptor_mismatch",
              chain: "sui",
              method: "sign_transaction",
              payloadKind: "transaction",
              sizeBytes: String(payload.length + 1),
              payloadDigest: sha256Digest(payload),
            });
          }
          if (request.type === "payload_upload_abort") {
            assert.equal(request.payloadRef, "payload_descriptor_mismatch");
            return abortResponse(request);
          }
          throw new Error(`unexpected ${request.type}`);
        },
      }),
    { code: "protocol_error" },
  );
  assert.equal(seen.at(-1).type, "payload_upload_abort");
});

test("payload delivery helper aborts a finalized payload after consumer failure without replacing the error", async () => {
  const payload = makePayload(8);
  const original = new TestPayloadDeliveryError("consumer_failed", "consumer failed");
  const seen = [];
  await assert.rejects(
    () =>
      runUpload(payload, {
        executor: async (request, assertResponse) => {
          seen.push(request);
          if (request.type === "payload_upload_begin") {
            return beginResponse(request, "upload_consumer_failure");
          }
          if (request.type === "payload_upload_chunk") {
            return chunkResponse(request, payload.length);
          }
          if (request.type === "payload_upload_finish") {
            return finishResponse(request, payload, "payload_consumer_failure");
          }
          if (request.type === "payload_upload_abort") {
            assert.equal(request.payloadRef, "payload_consumer_failure");
            return abortResponse(request);
          }
          throw new Error(`unexpected ${request.type}`);
        },
        consume: async () => {
          throw original;
        },
      }),
    (error) => error === original,
  );
  assert.equal(seen.at(-1).type, "payload_upload_abort");
});

test("payload delivery helper reports abort invalid_session on the original error", async () => {
  const payload = makePayload(8);
  let invalidated = false;
  await assert.rejects(
    () =>
      runUpload(payload, {
        onAbortInvalidSession: () => {
          invalidated = true;
        },
        executor: async (request, assertResponse) => {
          if (request.type === "payload_upload_begin") {
            return beginResponse(request, "upload_invalid_session");
          }
          if (request.type === "payload_upload_chunk") {
            return assertResponse({
              id: request.id,
              version: 1,
              type: "payload_upload_chunk_result",
              receivedBytes: "1",
            });
          }
          if (request.type === "payload_upload_abort") {
            return assertResponse({
              id: request.id,
              version: 1,
              type: "error",
              error: {
                code: "invalid_session",
                message: "Session expired.",
              },
            });
          }
          throw new Error(`unexpected ${request.type}`);
        },
      }),
    { code: "protocol_error" },
  );
  assert.equal(invalidated, true);
});

test("payload delivery helper freezes payload bytes at call start", async () => {
  const payload = makePayload(4096);
  const original = Buffer.from(payload);
  const uploadedChunks = [];
  await runUpload(payload, {
    digestPayload: async (bytes) => {
      payload.fill(0xff);
      return sha256Digest(bytes);
    },
    executor: async (request, assertResponse) => {
      if (request.type === "payload_upload_begin") {
        return beginResponse(request, "upload_frozen_bytes");
      }
      if (request.type === "payload_upload_chunk") {
        uploadedChunks.push(Buffer.from(request.chunk, "base64"));
        return assertResponse({
          id: request.id,
          version: 1,
          type: "payload_upload_chunk_result",
          receivedBytes: String(Buffer.concat(uploadedChunks).length),
        });
      }
      if (request.type === "payload_upload_finish") {
        return finishResponse(request, original, "payload_frozen_bytes");
      }
      throw new Error(`unexpected ${request.type}`);
    },
  });
  assert.deepEqual(Buffer.concat(uploadedChunks), original);
});

function runUpload(payload, options = {}) {
  const digestPayload = options.digestPayload ?? ((bytes) => sha256Digest(bytes));
  return withUploadedSignablePayload({
    sessionId: "session_abcdef",
    chain: "sui",
    method: "sign_transaction",
    payloadKind: SIGNABLE_PAYLOAD_KIND_TRANSACTION,
    payloadBytes: payload,
    capability: options.capabilityOverride ?? capability,
    executeUploadRequest: options.executor,
    digestPayload,
    encodeChunkBase64: (chunk) => Buffer.from(chunk).toString("base64"),
    makeError: (code, message) => new TestPayloadDeliveryError(code, message),
    errorCode: (error) => error?.code ?? null,
    onAbortInvalidSession: options.onAbortInvalidSession,
    consumeFinalizedPayload: options.consume ?? (async (descriptor) => descriptor),
  });
}

function beginResponse(request, uploadId) {
  return {
    id: request.id,
    version: 1,
    type: "payload_upload_begin_result",
    uploadId,
    receivedBytes: "0",
    chunkMaxBytes: "2048",
  };
}

function chunkResponse(request, receivedBytes) {
  return {
    id: request.id,
    version: 1,
    type: "payload_upload_chunk_result",
    receivedBytes: String(receivedBytes),
  };
}

function finishResponse(request, payload, payloadRef) {
  return {
    id: request.id,
    version: 1,
    type: "payload_upload_finish_result",
    payloadRef,
    chain: "sui",
    method: "sign_transaction",
    payloadKind: "transaction",
    sizeBytes: String(payload.length),
    payloadDigest: sha256Digest(payload),
  };
}

function abortResponse(request) {
  return {
    id: request.id,
    version: 1,
    type: "payload_upload_abort_result",
    status: "aborted",
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
