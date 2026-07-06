#include "sui/zklogin_signature.h"

#include <string.h>

#include "numeric/u64_decimal.h"

namespace signing {
namespace {

struct BcsWriter {
    uint8_t* output;
    size_t output_size;
    size_t cursor;
};

void clear_output(uint8_t* output, size_t output_size, size_t* written)
{
    if (output != nullptr && output_size > 0) {
        volatile uint8_t* cursor = output;
        while (output_size > 0) {
            *cursor++ = 0;
            --output_size;
        }
    }
    if (written != nullptr) {
        *written = 0;
    }
}

bool bounded_strlen(const char* value, size_t max_chars, size_t* length_out)
{
    if (value == nullptr || length_out == nullptr) {
        return false;
    }
    for (size_t index = 0; index <= max_chars; ++index) {
        if (value[index] == '\0') {
            *length_out = index;
            return true;
        }
    }
    return false;
}

bool append_byte(BcsWriter* writer, uint8_t value)
{
    if (writer == nullptr || writer->output == nullptr ||
        writer->cursor >= writer->output_size) {
        return false;
    }
    writer->output[writer->cursor++] = value;
    return true;
}

bool append_bytes(BcsWriter* writer, const uint8_t* value, size_t value_size)
{
    if (writer == nullptr || writer->output == nullptr ||
        value == nullptr ||
        value_size > writer->output_size ||
        writer->cursor > writer->output_size - value_size) {
        return false;
    }
    memcpy(writer->output + writer->cursor, value, value_size);
    writer->cursor += value_size;
    return true;
}

bool append_uleb128(BcsWriter* writer, size_t value)
{
    do {
        uint8_t byte = static_cast<uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
            byte |= 0x80U;
        }
        if (!append_byte(writer, byte)) {
            return false;
        }
    } while (value != 0);
    return true;
}

bool append_string(BcsWriter* writer, const char* value, size_t max_chars)
{
    size_t length = 0;
    if (!bounded_strlen(value, max_chars, &length) ||
        !append_uleb128(writer, length)) {
        return false;
    }
    return length == 0 ||
           append_bytes(writer, reinterpret_cast<const uint8_t*>(value), length);
}

bool append_u64_le(BcsWriter* writer, uint64_t value)
{
    for (size_t index = 0; index < 8; ++index) {
        if (!append_byte(writer, static_cast<uint8_t>((value >> (index * 8)) & 0xffU))) {
            return false;
        }
    }
    return true;
}

bool append_string_vector(
    BcsWriter* writer,
    const char values[][kSuiZkLoginProofPointBufferSize],
    size_t count)
{
    if (!append_uleb128(writer, count)) {
        return false;
    }
    for (size_t index = 0; index < count; ++index) {
        if (!append_string(writer, values[index], kSuiZkLoginProofPointBufferSize - 1)) {
            return false;
        }
    }
    return true;
}

bool append_proof_points(BcsWriter* writer, const SuiZkLoginProofPoints& proof_points)
{
    if (!append_string_vector(
            writer,
            proof_points.a,
            kSuiZkLoginProofPointACount) ||
        !append_uleb128(writer, kSuiZkLoginProofPointBOuterCount)) {
        return false;
    }
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        if (!append_string_vector(
                writer,
                proof_points.b[row],
                kSuiZkLoginProofPointBInnerCount)) {
            return false;
        }
    }
    return append_string_vector(
        writer,
        proof_points.c,
        kSuiZkLoginProofPointCCount);
}

bool append_signature_inputs(
    BcsWriter* writer,
    const SuiZkLoginSignatureInputs& inputs)
{
    return append_proof_points(writer, inputs.proof_points) &&
           append_string(
               writer,
               inputs.iss_base64_details.value,
               kSuiZkLoginIssBase64BufferSize - 1) &&
           append_byte(writer, inputs.iss_base64_details.index_mod4) &&
           append_string(
               writer,
               inputs.header_base64,
               kSuiZkLoginHeaderBase64BufferSize - 1) &&
           append_string(
               writer,
               inputs.address_seed,
               kSuiZkLoginAddressSeedBufferSize - 1);
}

bool append_byte_vector(
    BcsWriter* writer,
    const uint8_t* value,
    size_t value_size)
{
    return append_uleb128(writer, value_size) &&
           append_bytes(writer, value, value_size);
}

}  // namespace

SuiZkLoginSignatureBuildResult build_sui_zklogin_signature_envelope(
    const SuiZkLoginSignatureInputs& inputs,
    const char* max_epoch,
    const uint8_t* user_signature,
    size_t user_signature_size,
    uint8_t* output,
    size_t output_size,
    size_t* output_size_written)
{
    clear_output(output, output_size, output_size_written);
    if (output == nullptr || output_size_written == nullptr) {
        return SuiZkLoginSignatureBuildResult::invalid_input;
    }
    if (output_size < kSuiSignatureEnvelopeMaxBytes) {
        return SuiZkLoginSignatureBuildResult::output_too_small;
    }
    if (user_signature == nullptr ||
        user_signature_size != kSuiEd25519SignatureBytes ||
        user_signature[0] != kSuiSignatureSchemeFlagEd25519) {
        return SuiZkLoginSignatureBuildResult::invalid_input;
    }
    uint64_t parsed_max_epoch = 0;
    if (!parse_canonical_u64_decimal_string(max_epoch, &parsed_max_epoch)) {
        return SuiZkLoginSignatureBuildResult::invalid_input;
    }

    output[0] = kSuiSignatureSchemeFlagZkLogin;
    BcsWriter writer{
        output,
        kSuiSignatureEnvelopeMaxBytes,
        1,
    };
    if (!append_signature_inputs(&writer, inputs) ||
        !append_u64_le(&writer, parsed_max_epoch) ||
        !append_byte_vector(&writer, user_signature, user_signature_size)) {
        clear_output(output, output_size, output_size_written);
        return SuiZkLoginSignatureBuildResult::bcs_too_large;
    }
    if (writer.cursor <= 1 ||
        writer.cursor - 1 > kSuiZkLoginSignatureBcsMaxBytes) {
        clear_output(output, output_size, output_size_written);
        return SuiZkLoginSignatureBuildResult::bcs_too_large;
    }
    *output_size_written = writer.cursor;
    return SuiZkLoginSignatureBuildResult::ok;
}

const char* sui_zklogin_signature_build_result_name(
    SuiZkLoginSignatureBuildResult result)
{
    switch (result) {
        case SuiZkLoginSignatureBuildResult::ok:
            return "ok";
        case SuiZkLoginSignatureBuildResult::invalid_input:
            return "invalid_input";
        case SuiZkLoginSignatureBuildResult::output_too_small:
            return "output_too_small";
        case SuiZkLoginSignatureBuildResult::bcs_too_large:
            return "bcs_too_large";
    }
    return "unknown";
}

}  // namespace signing
