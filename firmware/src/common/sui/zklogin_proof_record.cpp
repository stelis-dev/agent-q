#include "sui/zklogin_proof_record.h"

#include <string.h>

#include "numeric/u64_decimal.h"
#include "sui/network.h"

extern "C" {
#include "byte_conversions.h"
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

constexpr const char* kMaxU256Decimal =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

void wipe_sensitive_buffer_local(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

bool bounded_c_string_length(const char* value, size_t max_chars, size_t* out)
{
    if (value == nullptr || out == nullptr) {
        return false;
    }
    for (size_t index = 0; index <= max_chars; ++index) {
        if (value[index] == '\0') {
            *out = index;
            return true;
        }
    }
    return false;
}

bool exact_c_string_length(const char* value, size_t expected)
{
    size_t length = 0;
    return bounded_c_string_length(value, expected, &length) && length == expected;
}

bool is_lower_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

bool is_valid_proof_hash(const char* value)
{
    constexpr const char* kPrefix = "sha256:";
    constexpr size_t kPrefixSize = 7;
    if (value == nullptr ||
        !exact_c_string_length(value, kSuiZkLoginProofHashBufferSize - 1) ||
        memcmp(value, kPrefix, kPrefixSize) != 0) {
        return false;
    }
    for (size_t index = kPrefixSize; index < kSuiZkLoginProofHashBufferSize - 1; ++index) {
        if (!is_lower_hex(value[index])) {
            return false;
        }
    }
    return true;
}

bool is_base64url_no_padding_char(char c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' ||
           c == '_';
}

bool is_base64url_no_padding_string(const char* value, size_t max_chars)
{
    size_t length = 0;
    if (!bounded_c_string_length(value, max_chars, &length) || length == 0) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (!is_base64url_no_padding_char(value[index])) {
            return false;
        }
    }
    return true;
}

bool is_canonical_decimal_string_with_max(const char* value, size_t max_digits)
{
    size_t length = 0;
    if (!bounded_c_string_length(value, max_digits, &length) || length == 0) {
        return false;
    }
    if (length > 1 && value[0] == '0') {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
}

bool decimal_string_lte(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    const size_t left_len = strlen(left);
    const size_t right_len = strlen(right);
    if (left_len != right_len) {
        return left_len < right_len;
    }
    return strcmp(left, right) <= 0;
}

bool is_canonical_u256_decimal_string(const char* value)
{
    return is_canonical_decimal_string_with_max(
               value,
               kSuiZkLoginAddressSeedBufferSize - 1) &&
           decimal_string_lte(value, kMaxU256Decimal);
}

bool parse_u256_decimal_to_be32(const char* value, uint8_t out[32])
{
    if (out != nullptr) {
        memset(out, 0, 32);
    }
    if (value == nullptr || out == nullptr || !is_canonical_u256_decimal_string(value)) {
        return false;
    }

    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        uint16_t carry = static_cast<uint16_t>(*cursor - '0');
        for (int index = 31; index >= 0; --index) {
            const uint16_t updated =
                static_cast<uint16_t>(out[index]) * 10u + carry;
            out[index] = static_cast<uint8_t>(updated & 0xFF);
            carry = static_cast<uint16_t>(updated >> 8);
        }
        if (carry != 0) {
            memset(out, 0, 32);
            return false;
        }
    }
    return true;
}

bool validate_proof_points(const SuiZkLoginProofPoints& points)
{
    for (size_t index = 0; index < kSuiZkLoginProofPointACount; ++index) {
        if (!is_canonical_decimal_string_with_max(
                points.a[index],
                kSuiZkLoginProofPointBufferSize - 1)) {
            return false;
        }
    }
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        for (size_t column = 0; column < kSuiZkLoginProofPointBInnerCount; ++column) {
            if (!is_canonical_decimal_string_with_max(
                    points.b[row][column],
                    kSuiZkLoginProofPointBufferSize - 1)) {
                return false;
            }
        }
    }
    for (size_t index = 0; index < kSuiZkLoginProofPointCCount; ++index) {
        if (!is_canonical_decimal_string_with_max(
                points.c[index],
                kSuiZkLoginProofPointBufferSize - 1)) {
            return false;
        }
    }
    return true;
}

bool validate_inputs(const SuiZkLoginSignatureInputs& inputs, const char* address_seed)
{
    return validate_proof_points(inputs.proof_points) &&
           inputs.iss_base64_details.index_mod4 <= 2 &&
           is_base64url_no_padding_string(
               inputs.iss_base64_details.value,
               kSuiZkLoginIssBase64BufferSize - 1) &&
           is_base64url_no_padding_string(
               inputs.header_base64,
               kSuiZkLoginHeaderBase64BufferSize - 1) &&
           is_canonical_u256_decimal_string(inputs.address_seed) &&
           address_seed != nullptr &&
           strcmp(inputs.address_seed, address_seed) == 0;
}

bool validate_public_identifier(const SuiZkLoginProofRecord& record)
{
    if (record.public_key_size < kSuiZkLoginPublicKeyMinBytes ||
        record.public_key_size > kSuiZkLoginPublicKeyMaxBytes ||
        record.public_key[0] != kSuiSignatureSchemeFlagZkLogin) {
        return false;
    }

    const size_t issuer_len = record.public_key[1];
    const size_t expected_size = 2 + issuer_len + 32;
    if (record.public_key_size != expected_size) {
        return false;
    }

    size_t stored_issuer_len = 0;
    if (!bounded_c_string_length(
            record.issuer,
            kSuiZkLoginIssuerBufferSize - 1,
            &stored_issuer_len) ||
        stored_issuer_len != issuer_len ||
        memcmp(record.public_key + 2, record.issuer, issuer_len) != 0) {
        return false;
    }

    uint8_t address_seed[32] = {};
    if (!parse_u256_decimal_to_be32(record.address_seed, address_seed)) {
        return false;
    }
    const bool seed_matches =
        memcmp(record.public_key + 2 + issuer_len, address_seed, sizeof(address_seed)) == 0;
    wipe_sensitive_buffer_local(address_seed, sizeof(address_seed));
    if (!seed_matches) {
        return false;
    }

    char derived_address[kSuiZkLoginAddressBufferSize] = {};
    return derive_sui_address_from_scheme_prefixed_public_key(
               record.public_key,
               record.public_key_size,
               derived_address,
               sizeof(derived_address)) &&
           strcmp(derived_address, record.address) == 0;
}

}  // namespace

bool sui_address_format_valid(const char* value)
{
    if (value == nullptr ||
        !exact_c_string_length(value, kSuiZkLoginAddressBufferSize - 1) ||
        value[0] != '0' ||
        value[1] != 'x') {
        return false;
    }
    for (size_t index = 2; index < kSuiZkLoginAddressBufferSize - 1; ++index) {
        if (!is_lower_hex(value[index])) {
            return false;
        }
    }
    return true;
}

bool derive_sui_address_from_scheme_prefixed_public_key(
    const uint8_t* public_key,
    size_t public_key_size,
    char* address_out,
    size_t address_out_size)
{
    if (address_out != nullptr && address_out_size > 0) {
        memset(address_out, 0, address_out_size);
    }
    if (public_key == nullptr || public_key_size == 0 ||
        address_out == nullptr || address_out_size < kSuiZkLoginAddressBufferSize) {
        return false;
    }

    uint8_t address[32] = {};
    crypto_blake2b(address, sizeof(address), public_key, public_key_size);
    address_out[0] = '0';
    address_out[1] = 'x';
    bytes_to_hex(address, sizeof(address), address_out + 2);
    wipe_sensitive_buffer_local(address, sizeof(address));
    return true;
}

bool validate_sui_zklogin_proof_record(const SuiZkLoginProofRecord* record)
{
    return record != nullptr &&
           sui_network_supported(record->network) &&
           sui_address_format_valid(record->address) &&
           is_canonical_u256_decimal_string(record->address_seed) &&
           is_canonical_u64_decimal_string(record->max_epoch) &&
           validate_inputs(record->inputs, record->address_seed) &&
           is_valid_proof_hash(record->proof_hash) &&
           validate_public_identifier(*record);
}

}  // namespace signing
