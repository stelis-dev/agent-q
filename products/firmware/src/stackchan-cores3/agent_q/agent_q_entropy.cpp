#include "agent_q_entropy.h"

#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>

#include "agent_q_bip39.h"
#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"

namespace agent_q {

namespace {

constexpr const char* kTag = "AgentQEntropy";
constexpr size_t kSecureRandomSeedBytes = 48;

mbedtls_hmac_drbg_context g_secure_rng;
bool g_secure_rng_initialized = false;

}  // namespace

bool init_secure_random_from_early_boot_entropy()
{
    if (g_secure_rng_initialized) {
        return true;
    }

    uint8_t seed[kSecureRandomSeedBytes] = {};
    bootloader_random_enable();
    esp_fill_random(seed, sizeof(seed));
    bootloader_random_disable();

    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        wipe_sensitive_buffer(seed, sizeof(seed));
        ESP_LOGE(kTag, "Could not initialize secure RNG: SHA-256 unavailable");
        return false;
    }

    mbedtls_hmac_drbg_init(&g_secure_rng);
    const int result = mbedtls_hmac_drbg_seed_buf(&g_secure_rng, md, seed, sizeof(seed));
    wipe_sensitive_buffer(seed, sizeof(seed));
    if (result != 0) {
        mbedtls_hmac_drbg_free(&g_secure_rng);
        ESP_LOGE(kTag, "Could not seed secure RNG: %d", result);
        return false;
    }

    g_secure_rng_initialized = true;
    ESP_LOGI(kTag, "Secure RNG seeded from early boot entropy");
    return true;
}

bool secure_random_ready()
{
    return g_secure_rng_initialized;
}

bool fill_secure_random(void* output, size_t size)
{
    if (!g_secure_rng_initialized || output == nullptr) {
        return false;
    }

    return mbedtls_hmac_drbg_random(&g_secure_rng, static_cast<unsigned char*>(output), size) == 0;
}

}  // namespace agent_q
