#include "secure_random.h"

#include <stdint.h>

#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "sensitive_memory.h"

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchRNG";
constexpr size_t kSeedBytes = 48;

mbedtls_hmac_drbg_context g_rng;
bool g_rng_initialized = false;

}  // namespace

bool secure_random_init()
{
    if (g_rng_initialized) {
        return true;
    }

    uint8_t seed[kSeedBytes] = {};
    bootloader_random_enable();
    esp_fill_random(seed, sizeof(seed));
    bootloader_random_disable();

    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        wipe_sensitive_buffer(seed, sizeof(seed));
        ESP_LOGE(kTag, "SHA-256 is unavailable for RNG seeding");
        return false;
    }

    mbedtls_hmac_drbg_init(&g_rng);
    const int result = mbedtls_hmac_drbg_seed_buf(&g_rng, md, seed, sizeof(seed));
    wipe_sensitive_buffer(seed, sizeof(seed));
    if (result != 0) {
        mbedtls_hmac_drbg_free(&g_rng);
        ESP_LOGE(kTag, "RNG seed failed: %d", result);
        return false;
    }

    g_rng_initialized = true;
    ESP_LOGI(kTag, "Secure RNG initialized");
    return true;
}

bool secure_random_ready()
{
    return g_rng_initialized;
}

bool secure_random_fill(void* output, size_t size)
{
    if (!g_rng_initialized || output == nullptr) {
        return false;
    }
    return mbedtls_hmac_drbg_random(&g_rng, static_cast<unsigned char*>(output), size) == 0;
}

}  // namespace stopwatch_target
