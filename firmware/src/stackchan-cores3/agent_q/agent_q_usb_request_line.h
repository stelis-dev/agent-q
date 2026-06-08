#pragma once

#include <stddef.h>

namespace agent_q {

// Framing for the newline-delimited request stream from the host. One JSON object per
// line; a leading/trailing newline isolates partial bytes left by a failed write. This
// per-byte accumulator is the read side of that framing and is intentionally robust:
//
//   - bounded:        an over-long line is rejected and skipped to the next newline, so
//                     a malformed/never-terminated stream cannot grow the buffer.
//   - resynchronising: a rejected line is discarded up to the next newline, after which
//                     parsing resumes cleanly (no permanent desync from one bad frame).
//   - delimiter-safe: NUL bytes are rejected (JSON never contains a raw NUL), so a
//                     binary/garbled stream cannot smuggle a frame boundary.
//
// (A length-prefix reframe would lose the resync property; COBS adds nothing over this
// for newline-free JSON. The robustness goal is met by the framing above.)
//
// Pure logic over caller-owned state so it is exhaustively host-tested.

enum class AgentQUsbLineFeedResult {
    none,               // byte ignored or accumulated; no complete line yet
    line_ready,         // a complete, NUL-terminated line is in `buffer`
    rejected_nul,       // the line held a NUL byte; it is discarded to the next newline
    rejected_too_long,  // the line exceeded `capacity`; it is discarded to the next newline
};

// Feed one byte. `buffer`/`capacity` is the line store; `*size` is the bytes held so far;
// `*discarding` tracks a rejected line being skipped to the next newline.
AgentQUsbLineFeedResult usb_request_line_feed(
    char c,
    char* buffer,
    size_t capacity,
    size_t* size,
    bool* discarding);

}  // namespace agent_q
