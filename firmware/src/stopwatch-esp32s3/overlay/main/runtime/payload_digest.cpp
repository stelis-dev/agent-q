#include "payload_digest.h"

#include <stdio.h>
#include <string.h>

#include "sensitive_memory.h"
#include "mbedtls/sha256.h"

namespace stopwatch_target {

bool payload_digest_sha256(const uint8_t* data, size_t size, char out[kPayloadDigestSize])
{
    if (out != nullptr) {
        memset(out, 0, kPayloadDigestSize);
    }
    if (data == nullptr || size == 0 || out == nullptr) {
        return false;
    }

    uint8_t digest[32] = {};
    if (mbedtls_sha256(data, size, digest, 0) != 0) {
        wipe_sensitive_buffer(digest, sizeof(digest));
        return false;
    }

    int written = snprintf(
        out,
        kPayloadDigestSize,
        "sha256:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
        digest[5],
        digest[6],
        digest[7],
        digest[8],
        digest[9],
        digest[10],
        digest[11],
        digest[12],
        digest[13],
        digest[14],
        digest[15],
        digest[16],
        digest[17],
        digest[18],
        digest[19],
        digest[20],
        digest[21],
        digest[22],
        digest[23],
        digest[24],
        digest[25],
        digest[26],
        digest[27],
        digest[28],
        digest[29],
        digest[30],
        digest[31]);
    wipe_sensitive_buffer(digest, sizeof(digest));
    return written == static_cast<int>(kPayloadDigestSize - 1);
}

}  // namespace stopwatch_target
