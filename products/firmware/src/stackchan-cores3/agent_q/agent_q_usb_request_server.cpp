#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_bip39.h"
#include "agent_q_display_power.h"
#include "agent_q_entropy.h"
#include "agent_q_root_material.h"
#include "agent_q_speech_bubble.h"
#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "hal/board/hal_bridge.h"
#include "hal/hal.h"
#include "lvgl.h"
#include "nvs.h"

#include "stackchan/stackchan.h"

namespace {

constexpr const char* kTag = "UsbRequestServer";
constexpr int kProtocolVersion = 1;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stackchan-cores3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kDeviceIdKey = "device_id";
constexpr const char* kProvisioningStateKey = "prov_state";
constexpr const char* kProvisioningStateUnprovisioned = "unprovisioned";
constexpr const char* kProvisioningStateProvisioning = "provisioning";
constexpr const char* kProvisioningStateProvisioned = "provisioned";
constexpr uint32_t kDisplaySignalTimeoutMs = 30000;
constexpr uint32_t kIdentifyDisplayDefaultMs = 10000;
constexpr uint32_t kIdentifyDisplayMaxMs = 30000;
constexpr uint32_t kConnectApprovalDefaultMs = 30000;
constexpr uint32_t kConnectApprovalMaxMs = 60000;
constexpr uint32_t kProvisioningApprovalDefaultMs = 30000;
constexpr uint32_t kProvisioningApprovalMaxMs = 60000;
constexpr uint32_t kRecoveryPhraseDisplayMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kSessionTtlMs = 1800000;
constexpr uint32_t kSessionExpiryCheckMs = 5000;
constexpr size_t kLineBufferSize = 512;
constexpr size_t kResponseBufferSize = 512;
constexpr size_t kMaxRequestIdSize = 80;
constexpr size_t kDeviceIdSize = 37;
constexpr size_t kProvisioningStateSize = 16;
constexpr size_t kIdentifyCodeSize = 5;
constexpr size_t kSessionIdSize = 26;
constexpr size_t kGatewayNameSize = 65;
constexpr size_t kConnectDisplayMessageSize = 96;
constexpr size_t kPendingDisplayMessageSize = kLineBufferSize;
constexpr size_t kRecoveryPhrasePrefixCellCount = 12;
constexpr size_t kRecoveryPhrasePrefixCellSize = 8;
constexpr int kScreenHeight = 240;
constexpr int kScreenWidth = 320;
constexpr int kTopDecisionStripHeight = 34;
constexpr int kTopDecisionPanelHeight = kTopDecisionStripHeight;
constexpr int kTopDecisionButtonWidth = kScreenWidth / 2;
constexpr int kTopDecisionCornerRadius = 10;
constexpr uint32_t kAgentQResultDisplayMs = 1800;
constexpr uint32_t kAgentQHeadLiftMs = 900;
constexpr int kAgentQHeadLiftPitchDelta = 160;
constexpr int kAgentQHeadLiftSpeed = 280;

enum class AgentQUiPanelKind {
    none,
    top_decision,
    recovery_phrase_display,
};

enum class AgentQUiMode {
    none,
    decision,
    result,
    identification,
};

enum class AgentQMessageKind {
    info,
    approval,
    success,
    rejected,
    timeout,
    error,
};

enum class PendingChoice {
    none,
    yes,
    no,
};

enum class AgentQUiEventKind {
    panel_deleted,
    setup_requested,
    provisioning_welcome_requested,
};

struct AgentQUiEvent {
    AgentQUiEventKind kind = AgentQUiEventKind::panel_deleted;
    AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none;
};

enum class PendingKind {
    none,
    display_signal,
    connect,
    factory_reset,
    start_provisioning,
    cancel_provisioning,
    confirm_recovery_phrase_backup,
};

enum class ProvisioningRuntimeState {
    unprovisioned,
    provisioning,
    provisioned,
};

// Firmware-owned state is kept separate from StackChan-owned avatar/app state.
// Agent-Q records protocol/UI ownership here and only stores StackChan
// references for temporary objects it created and must remove.
struct PendingApprovalState {
    char id[kMaxRequestIdSize] = {};
    char gateway_name[kGatewayNameSize] = {};
    char display_message[kPendingDisplayMessageSize] = {};
    bool active = false;
    bool touch_armed = false;
    TickType_t deadline = 0;
    PendingChoice choice = PendingChoice::none;
    PendingKind kind = PendingKind::none;

    bool awaiting_choice() const
    {
        return active && choice == PendingChoice::none;
    }

    void clear()
    {
        id[0] = '\0';
        gateway_name[0] = '\0';
        display_message[0] = '\0';
        active = false;
        touch_armed = false;
        deadline = 0;
        choice = PendingChoice::none;
        kind = PendingKind::none;
    }

    void begin_connect(const char* request_id, const char* request_gateway_name, uint32_t timeout_ms)
    {
        clear();
        strlcpy(id, request_id, sizeof(id));
        strlcpy(gateway_name, request_gateway_name, sizeof(gateway_name));
        active = true;
        kind = PendingKind::connect;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    }

    void begin_display_signal(const char* request_id, const char* message)
    {
        clear();
        strlcpy(id, request_id, sizeof(id));
        strlcpy(display_message, message != nullptr ? message : "USB request", sizeof(display_message));
        active = true;
        kind = PendingKind::display_signal;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kDisplaySignalTimeoutMs);
    }

    void begin_provisioning_transition(const char* request_id, PendingKind request_kind, uint32_t timeout_ms)
    {
        clear();
        strlcpy(id, request_id, sizeof(id));
        active = true;
        kind = request_kind;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    }

    void begin_factory_reset(const char* request_id, uint32_t timeout_ms)
    {
        begin_provisioning_transition(request_id, PendingKind::factory_reset, timeout_ms);
    }

    void begin_recovery_phrase_step(const char* request_id, PendingKind request_kind, uint32_t timeout_ms)
    {
        clear();
        strlcpy(id, request_id, sizeof(id));
        active = true;
        kind = request_kind;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    }
};

struct IdentificationState {
    char code[kIdentifyCodeSize] = {};
    bool active = false;
    TickType_t deadline = 0;

    void clear()
    {
        code[0] = '\0';
        active = false;
        deadline = 0;
    }

    void begin(const char* value, uint32_t duration_ms)
    {
        strlcpy(code, value, sizeof(code));
        active = true;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms);
    }
};

struct SessionState {
    char id[kSessionIdSize] = {};
    TickType_t expiry = 0;
    TickType_t next_expiry_check = 0;

    void clear()
    {
        id[0] = '\0';
        expiry = 0;
    }

    bool active() const
    {
        return id[0] != '\0' && expiry != 0;
    }
};

struct AgentQUiState {
    lv_obj_t* panel = nullptr;
    AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none;
    stackchan::avatar::Avatar* speech_avatar = nullptr;
    int speech_decorator_id = -1;
    AgentQUiMode speech_mode = AgentQUiMode::none;
    stackchan::avatar::Emotion previous_emotion = stackchan::avatar::Emotion::Neutral;
    bool owns_emotion = false;
    TickType_t message_deadline = 0;
};

enum class RecoveryPhraseScratchStage {
    none,
    displayed,
    backup_confirmation_pending,
};

enum class RecoveryPhraseGenerationResult {
    ok,
    rng_error,
    generation_error,
};

struct ProvisioningScratchState {
    uint8_t root_material[agent_q::kRootMaterialBytes] = {};
    char recovery_phrase[agent_q::kBip39MnemonicMaxChars] = {};
    char recovery_phrase_prefix_cells[kRecoveryPhrasePrefixCellCount][kRecoveryPhrasePrefixCellSize] = {};
    RecoveryPhraseScratchStage recovery_phrase_stage = RecoveryPhraseScratchStage::none;
    TickType_t recovery_phrase_deadline = 0;

    void wipe()
    {
        agent_q::wipe_sensitive_buffer(root_material, sizeof(root_material));
        agent_q::wipe_sensitive_buffer(recovery_phrase, sizeof(recovery_phrase));
        agent_q::wipe_sensitive_buffer(
            recovery_phrase_prefix_cells,
            kRecoveryPhrasePrefixCellCount * kRecoveryPhrasePrefixCellSize);
        recovery_phrase_stage = RecoveryPhraseScratchStage::none;
        recovery_phrase_deadline = 0;
    }

    bool has_recovery_phrase() const
    {
        return recovery_phrase_stage != RecoveryPhraseScratchStage::none;
    }
};

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
char g_device_id[kDeviceIdSize];
ProvisioningRuntimeState g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
bool g_root_material_consistency_error = false;
PendingApprovalState g_pending;
IdentificationState g_identification;
SessionState g_session;
AgentQUiState g_ui;
ProvisioningScratchState g_provisioning_scratch;
bool g_usb_ready = false;
TaskHandle_t g_usb_task = nullptr;
QueueHandle_t g_pending_choice_queue = nullptr;
QueueHandle_t g_ui_event_queue = nullptr;

bool recovery_phrase_display_active();
bool recovery_phrase_flow_active();
bool persist_provisioning_state(ProvisioningRuntimeState next_state);

void wipe_recovery_phrase_scratch(const char* reason)
{
    const bool had_recovery_phrase = g_provisioning_scratch.has_recovery_phrase();
    g_provisioning_scratch.wipe();
    if (had_recovery_phrase) {
        ESP_LOGW(kTag, "Recovery phrase scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

bool is_decision_panel_kind(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::top_decision;
}

bool tick_reached(TickType_t deadline)
{
    return static_cast<int32_t>(xTaskGetTickCount() - deadline) >= 0;
}

int clamp_int(int value, int min_value, int max_value)
{
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

class AgentQHeadLiftModifier : public stackchan::TimedEventModifier {
public:
    AgentQHeadLiftModifier() : stackchan::TimedEventModifier(kAgentQHeadLiftMs)
    {
    }

    void _on_start(stackchan::Modifiable& stackchan) override
    {
        auto& motion = stackchan.motion();
        if (motion.isModifyLocked() || motion.isMoving()) {
            return;
        }

        const auto current = motion.getCurrentAngles();
        previous_yaw_ = current.x;
        previous_pitch_ = current.y;
        active_ = true;

        motion.setModifyLock(true);
        const int target_pitch = clamp_int(previous_pitch_ + kAgentQHeadLiftPitchDelta, 0, 540);
        motion.moveWithSpeed(previous_yaw_, target_pitch, kAgentQHeadLiftSpeed);
    }

    void _on_end(stackchan::Modifiable& stackchan) override
    {
        if (!active_) {
            return;
        }

        auto& motion = stackchan.motion();
        motion.moveWithSpeed(previous_yaw_, previous_pitch_, kAgentQHeadLiftSpeed);
        motion.setModifyLock(false);
        active_ = false;
    }

private:
    bool active_ = false;
    int previous_yaw_ = 0;
    int previous_pitch_ = 0;
};

bool is_safe_id(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= kMaxRequestIdSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool is_safe_identification_code(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    for (size_t index = 0; index < 4; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return value[4] == '\0';
}

bool is_printable_ascii_gateway_name(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= kGatewayNameSize) {
            return false;
        }
        const unsigned char c = static_cast<unsigned char>(*cursor);
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

void wipe_recovery_phrase_prefix_cells(char cells[kRecoveryPhrasePrefixCellCount][kRecoveryPhrasePrefixCellSize])
{
    agent_q::wipe_sensitive_buffer(
        cells, kRecoveryPhrasePrefixCellCount * kRecoveryPhrasePrefixCellSize);
}

bool format_recovery_phrase_prefix_cells(
    const char* phrase,
    char cells[kRecoveryPhrasePrefixCellCount][kRecoveryPhrasePrefixCellSize])
{
    if (phrase == nullptr || cells == nullptr) {
        return false;
    }

    wipe_recovery_phrase_prefix_cells(cells);
    size_t word_count = 0;
    const char* cursor = phrase;
    while (*cursor != '\0') {
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        char prefix[5] = {};
        size_t prefix_length = 0;
        while (*cursor != '\0' && *cursor != ' ') {
            if (prefix_length < 4) {
                prefix[prefix_length++] = *cursor;
            }
            cursor++;
        }
        word_count++;
        if (word_count > 12) {
            wipe_recovery_phrase_prefix_cells(cells);
            return false;
        }

        const int written = snprintf(
            cells[word_count - 1],
            kRecoveryPhrasePrefixCellSize,
            "%s",
            prefix);
        if (written <= 0 || static_cast<size_t>(written) >= kRecoveryPhrasePrefixCellSize) {
            wipe_recovery_phrase_prefix_cells(cells);
            return false;
        }
    }

    if (word_count != 12) {
        wipe_recovery_phrase_prefix_cells(cells);
        return false;
    }
    return true;
}

bool is_safe_session_id(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    const char* expected_prefix = "session_";
    const size_t prefix_length = 8;
    for (size_t index = 0; index < prefix_length; ++index) {
        if (value[index] != expected_prefix[index]) {
            return false;
        }
    }
    size_t length = prefix_length;
    for (const char* cursor = value + prefix_length; *cursor != '\0'; ++cursor) {
        if (++length >= kSessionIdSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) {
            return false;
        }
    }
    return length > prefix_length;
}

void write_json_document(JsonDocument& response)
{
    char buffer[kResponseBufferSize];
    size_t len = serializeJson(response, buffer, sizeof(buffer) - 2);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    usb_serial_jtag_write_bytes(buffer, len, pdMS_TO_TICKS(20));
    usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(50));
}

void write_error_response(const char* id, const char* code, const char* message)
{
    JsonDocument response;
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = kProtocolVersion;
    response["type"] = "error";
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    write_json_document(response);
}

const char* current_device_state()
{
    if (g_root_material_consistency_error) {
        return "error";
    }
    if (g_pending.active) {
        return "awaiting_approval";
    }
    if (recovery_phrase_display_active()) {
        return "busy";
    }
    return "idle";
}

const char* provisioning_state_to_string(ProvisioningRuntimeState state)
{
    switch (state) {
        case ProvisioningRuntimeState::provisioned:
            return kProvisioningStateProvisioned;
        case ProvisioningRuntimeState::provisioning:
            return kProvisioningStateProvisioning;
        case ProvisioningRuntimeState::unprovisioned:
        default:
            return kProvisioningStateUnprovisioned;
    }
}

bool parse_provisioning_state(const char* value, ProvisioningRuntimeState* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    if (strcmp(value, kProvisioningStateUnprovisioned) == 0) {
        *output = ProvisioningRuntimeState::unprovisioned;
        return true;
    }
    if (strcmp(value, kProvisioningStateProvisioning) == 0) {
        *output = ProvisioningRuntimeState::provisioning;
        return true;
    }
    if (strcmp(value, kProvisioningStateProvisioned) == 0) {
        *output = ProvisioningRuntimeState::provisioned;
        return true;
    }
    return false;
}

void write_status_response(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "status";
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = current_device_state();
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    response["provisioning"]["state"] = provisioning_state_to_string(g_provisioning_state);
    write_json_document(response);
}

void write_identify_device_result(const char* id, const char* code)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "identify_device_result";
    response["status"] = "displayed";
    response["code"] = code;
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = current_device_state();
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    write_json_document(response);
}

void write_display_signal_result(const char* id, const char* status, const char* error_code, const char* error_message)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "display_signal_result";
    response["status"] = status;
    if (error_code != nullptr) {
        response["error"]["code"] = error_code;
        response["error"]["message"] = error_message;
    }
    write_json_document(response);
}

void write_connect_approved_response(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "connect_result";
    response["status"] = "approved";
    response["sessionId"] = g_session.id;
    response["sessionTtlMs"] = kSessionTtlMs;
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = "idle";
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    write_json_document(response);
}

void write_connect_rejected_response(const char* id, const char* error_code, const char* error_message)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "connect_result";
    response["status"] = "rejected";
    response["error"]["code"] = error_code;
    response["error"]["message"] = error_message;
    write_json_document(response);
}

void write_disconnect_result(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "disconnect_result";
    response["status"] = "disconnected";
    write_json_document(response);
}

void write_factory_reset_result(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "factory_reset_result";
    response["status"] = "reset";
    response["provisioning"]["state"] = provisioning_state_to_string(g_provisioning_state);
    write_json_document(response);
}

void write_provisioning_result(const char* id, const char* status)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "provisioning_result";
    response["status"] = status;
    response["provisioning"]["state"] = provisioning_state_to_string(g_provisioning_state);
    write_json_document(response);
}

void write_recovery_phrase_result(const char* id, const char* status)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "recovery_phrase_result";
    response["status"] = status;
    response["provisioning"]["state"] = provisioning_state_to_string(g_provisioning_state);
    write_json_document(response);
}

bool fill_protocol_random(void* output, size_t size, const char* purpose)
{
    if (agent_q::fill_secure_random(output, size)) {
        return true;
    }

    ESP_LOGE(kTag, "Secure RNG unavailable for %s", purpose != nullptr ? purpose : "protocol random");
    return false;
}

bool format_session_id(char* output, size_t output_size)
{
    uint8_t bytes[8] = {};
    if (!fill_protocol_random(bytes, sizeof(bytes), "session id")) {
        return false;
    }
    snprintf(output,
             output_size,
             "session_%02x%02x%02x%02x%02x%02x%02x%02x",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3],
             bytes[4],
             bytes[5],
             bytes[6],
             bytes[7]);
    agent_q::wipe_sensitive_buffer(bytes, sizeof(bytes));
    return true;
}

void clear_active_session()
{
    g_session.clear();
}

bool replace_active_session()
{
    char next_id[kSessionIdSize] = {};
    if (!format_session_id(next_id, sizeof(next_id))) {
        return false;
    }
    snprintf(g_session.id, sizeof(g_session.id), "%s", next_id);
    g_session.expiry = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionTtlMs);
    return true;
}

void expire_session_if_needed()
{
    if (!tick_reached(g_session.next_expiry_check)) {
        return;
    }
    g_session.next_expiry_check = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionExpiryCheckMs);

    if (!g_session.active()) {
        return;
    }
    if (tick_reached(g_session.expiry)) {
        clear_active_session();
    }
}

bool format_uuid_v4(char* output, size_t output_size)
{
    uint8_t bytes[16] = {};
    if (!fill_protocol_random(bytes, sizeof(bytes), "device id")) {
        return false;
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    snprintf(output,
             output_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3],
             bytes[4],
             bytes[5],
             bytes[6],
             bytes[7],
             bytes[8],
             bytes[9],
             bytes[10],
             bytes[11],
             bytes[12],
             bytes[13],
             bytes[14],
             bytes[15]);
    agent_q::wipe_sensitive_buffer(bytes, sizeof(bytes));
    return true;
}

void load_or_create_device_id()
{
    g_device_id[0] = '\0';

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed for device id: %s", esp_err_to_name(result));
        if (!format_uuid_v4(g_device_id, sizeof(g_device_id))) {
            ESP_LOGE(kTag, "Could not create volatile device id");
        }
        return;
    }

    size_t length = sizeof(g_device_id);
    result = nvs_get_str(nvs, kDeviceIdKey, g_device_id, &length);
    if (result == ESP_OK && g_device_id[0] != '\0') {
        nvs_close(nvs);
        ESP_LOGI(kTag, "Loaded device id from NVS");
        return;
    }

    if (!format_uuid_v4(g_device_id, sizeof(g_device_id))) {
        ESP_LOGE(kTag, "Could not create device id");
        nvs_close(nvs);
        return;
    }
    result = nvs_set_str(nvs, kDeviceIdKey, g_device_id);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for device id: %s", esp_err_to_name(result));
    } else {
        ESP_LOGI(kTag, "Created device id in NVS");
    }
    nvs_close(nvs);
}

void load_provisioning_state()
{
    g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
    g_root_material_consistency_error = false;

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed for provisioning state: %s", esp_err_to_name(result));
        g_root_material_consistency_error = true;
        return;
    }

    char stored_state[kProvisioningStateSize] = {};
    size_t length = sizeof(stored_state);
    result = nvs_get_str(nvs, kProvisioningStateKey, stored_state, &length);
    nvs_close(nvs);

    if (result == ESP_ERR_NVS_NOT_FOUND) {
        if (agent_q::has_root_material()) {
            g_root_material_consistency_error = true;
            ESP_LOGE(kTag, "Root material exists without provisioning state; failing closed");
        }
        ESP_LOGI(kTag, "Provisioning state not found in NVS; using unprovisioned");
        return;
    }
    if (result != ESP_OK) {
        g_root_material_consistency_error = true;
        ESP_LOGE(kTag, "Provisioning state could not be read; failing closed");
        ESP_LOGW(kTag, "NVS read failed for provisioning state: %s", esp_err_to_name(result));
        return;
    }

    ProvisioningRuntimeState parsed = ProvisioningRuntimeState::unprovisioned;
    if (!parse_provisioning_state(stored_state, &parsed)) {
        if (agent_q::has_root_material()) {
            g_root_material_consistency_error = true;
            ESP_LOGE(kTag, "Unknown provisioning state with root material present; failing closed");
        } else {
            ESP_LOGW(kTag, "Unknown provisioning state in NVS; resetting to unprovisioned");
            persist_provisioning_state(ProvisioningRuntimeState::unprovisioned);
        }
        return;
    }

    const bool has_root = agent_q::has_root_material();
    if (parsed == ProvisioningRuntimeState::provisioned) {
        if (has_root) {
            g_provisioning_state = ProvisioningRuntimeState::provisioned;
        } else {
            g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
            g_root_material_consistency_error = true;
            ESP_LOGE(kTag, "Stored provisioned state has no valid root material; failing closed");
        }
    } else if (has_root) {
        g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
        g_root_material_consistency_error = true;
        ESP_LOGE(kTag, "Root material exists without provisioned state; failing closed");
    } else if (parsed == ProvisioningRuntimeState::provisioning) {
        g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
        ESP_LOGW(kTag, "Resetting legacy provisioning state for persistent root material flow");
        persist_provisioning_state(ProvisioningRuntimeState::unprovisioned);
    } else {
        g_provisioning_state = parsed;
    }
    ESP_LOGI(kTag, "Loaded provisioning state from NVS: %s", provisioning_state_to_string(g_provisioning_state));
}

bool persist_provisioning_state(ProvisioningRuntimeState next_state)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while saving provisioning state: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_str(nvs, kProvisioningStateKey, provisioning_state_to_string(next_state));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for provisioning state: %s", esp_err_to_name(result));
        return false;
    }

    g_provisioning_state = next_state;
    ESP_LOGI(kTag, "Stored provisioning state: %s", provisioning_state_to_string(g_provisioning_state));
    return true;
}

bool wipe_provisioning_scratch_state()
{
    wipe_recovery_phrase_scratch("provisioning scratch wipe");
    return true;
}

bool reset_device_to_unprovisioned()
{
    clear_active_session();
    wipe_provisioning_scratch_state();

    if (!agent_q::wipe_root_material()) {
        g_root_material_consistency_error = true;
        return false;
    }

    if (!persist_provisioning_state(ProvisioningRuntimeState::unprovisioned)) {
        g_root_material_consistency_error = true;
        return false;
    }

    g_root_material_consistency_error = false;
    return true;
}

bool provisioning_transition_allowed(PendingKind request_kind)
{
    switch (request_kind) {
        case PendingKind::start_provisioning:
            return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
                   !g_root_material_consistency_error &&
                   !recovery_phrase_flow_active();
        case PendingKind::cancel_provisioning:
            return g_provisioning_state == ProvisioningRuntimeState::provisioning ||
                   recovery_phrase_flow_active();
        case PendingKind::none:
        case PendingKind::display_signal:
        case PendingKind::factory_reset:
        case PendingKind::confirm_recovery_phrase_backup:
        default:
            return false;
    }
}

bool recovery_phrase_flow_active()
{
    return g_provisioning_scratch.has_recovery_phrase();
}

bool start_provisioning_busy()
{
    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !g_root_material_consistency_error &&
           recovery_phrase_flow_active();
}

bool recovery_phrase_confirmation_pending()
{
    return g_provisioning_scratch.recovery_phrase_stage == RecoveryPhraseScratchStage::backup_confirmation_pending &&
           g_pending.active && g_pending.kind == PendingKind::confirm_recovery_phrase_backup;
}

bool recovery_phrase_display_panel_active()
{
    LvglLockGuard lock;
    return g_ui.panel != nullptr && g_ui.panel_kind == AgentQUiPanelKind::recovery_phrase_display;
}

bool recovery_phrase_backup_confirmation_ready()
{
    return g_provisioning_scratch.recovery_phrase_stage == RecoveryPhraseScratchStage::displayed &&
           recovery_phrase_display_panel_active();
}

bool recovery_phrase_display_active()
{
    return recovery_phrase_backup_confirmation_ready();
}

void write_invalid_provisioning_state_response(const char* id, PendingKind request_kind)
{
    if (request_kind == PendingKind::start_provisioning) {
        write_error_response(id, "invalid_state", "Provisioning can start only from unprovisioned state.");
        return;
    }
    if (request_kind == PendingKind::cancel_provisioning) {
        write_error_response(id, "invalid_state", "Provisioning can be canceled only while setup is active.");
        return;
    }
    write_error_response(id, "invalid_state", "Invalid provisioning state transition.");
}

void write_invalid_recovery_phrase_state_response(const char* id)
{
    write_error_response(id, "invalid_state", "Recovery phrase backup confirmation is valid only during mnemonic setup.");
}

void write_recovery_phrase_not_ready_response(const char* id)
{
    write_error_response(id, "invalid_setup_step", "No displayed recovery phrase is ready for backup confirmation.");
}

void enqueue_pending_choice(PendingChoice choice)
{
    if (choice == PendingChoice::none || g_pending_choice_queue == nullptr) {
        return;
    }
    if (xQueueSend(g_pending_choice_queue, &choice, 0) != pdTRUE) {
        ESP_LOGW(kTag, "Pending choice queue is full");
    }
}

void enqueue_ui_event(AgentQUiEventKind kind, AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none)
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent event;
    event.kind = kind;
    event.panel_kind = panel_kind;
    if (xQueueSend(g_ui_event_queue, &event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void enqueue_ui_panel_deleted(AgentQUiPanelKind panel_kind)
{
    enqueue_ui_event(AgentQUiEventKind::panel_deleted, panel_kind);
}

void enqueue_setup_requested()
{
    enqueue_ui_event(AgentQUiEventKind::setup_requested);
}

void enqueue_provisioning_welcome_requested()
{
    enqueue_ui_event(AgentQUiEventKind::provisioning_welcome_requested);
}

void on_yes_clicked(lv_event_t*)
{
    enqueue_pending_choice(PendingChoice::yes);
}

void on_no_clicked(lv_event_t*)
{
    enqueue_pending_choice(PendingChoice::no);
}

void on_setup_clicked(lv_event_t*)
{
    enqueue_setup_requested();
}

void clear_agent_q_avatar_ui();

void make_button_label_with_font(lv_obj_t* button, const char* text, const lv_font_t* font, lv_event_cb_t callback)
{
    lv_obj_t* label = lv_label_create(button);
    lv_obj_remove_style_all(label);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_remove_flag(label, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(label, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
    lv_obj_center(label);
    lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(label, callback, LV_EVENT_CLICKED, nullptr);
}

void make_top_decision_button(lv_obj_t* parent, const char* text, int x, lv_color_t color, lv_event_cb_t callback)
{
    // A plain clickable object avoids themed button shadows/scrollbars that can
    // show up as stray vertical lines over the avatar.
    lv_obj_t* button = lv_obj_create(parent);
    lv_obj_remove_style_all(button);
    lv_obj_set_size(button, kTopDecisionButtonWidth, kTopDecisionStripHeight);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, 0);
    lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_remove_flag(button, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(button, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(button, 0, 0);
    lv_obj_set_style_border_width(button, 0, 0);
    lv_obj_set_style_outline_width(button, 0, 0);
    lv_obj_set_style_shadow_width(button, 0, 0);
    lv_obj_set_style_pad_all(button, 0, 0);
    lv_obj_set_style_bg_color(button, color, 0);
    lv_obj_set_style_bg_opa(button, LV_OPA_COVER, 0);
    lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, nullptr);
    make_button_label_with_font(button, text, &lv_font_montserrat_14, callback);
}

void trigger_agent_q_head_lift()
{
    GetStackChan().addModifier(std::make_unique<AgentQHeadLiftModifier>());
}

void on_agent_q_panel_deleted(lv_event_t* event)
{
    lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_target(event));
    if (g_ui.panel == target) {
        const AgentQUiPanelKind deleted_kind = g_ui.panel_kind;
        ESP_LOGW(kTag, "Agent-Q panel was deleted by external UI state");
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
        enqueue_ui_panel_deleted(deleted_kind);
    }
}

void register_agent_q_panel_locked(AgentQUiPanelKind kind)
{
    g_ui.panel_kind = kind;
    lv_obj_add_event_cb(g_ui.panel, on_agent_q_panel_deleted, LV_EVENT_DELETE, nullptr);
}

void clear_panel_locked()
{
    if (g_ui.panel != nullptr) {
        lv_obj_t* panel = g_ui.panel;
        const AgentQUiPanelKind panel_kind = g_ui.panel_kind;
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
        const bool wipe_recovery_phrase_after_delete =
            panel_kind == AgentQUiPanelKind::recovery_phrase_display &&
            !recovery_phrase_confirmation_pending();
        lv_obj_delete(panel);
        if (wipe_recovery_phrase_after_delete) {
            wipe_recovery_phrase_scratch("recovery phrase panel cleared");
        }
    } else {
        g_ui.panel_kind = AgentQUiPanelKind::none;
    }
}

struct AgentQMessagePresentation {
    lv_color_t background;
    lv_color_t foreground;
    stackchan::avatar::Emotion emotion;
    bool lift_head;
};

AgentQMessagePresentation agent_q_message_presentation(AgentQMessageKind kind)
{
    switch (kind) {
        case AgentQMessageKind::approval:
            return {
                lv_color_hex(0xFFD166), lv_color_hex(0x3A2B00), stackchan::avatar::Emotion::Neutral, true};
        case AgentQMessageKind::success:
            return {
                lv_color_hex(0x7DE2A6), lv_color_hex(0x063A1D), stackchan::avatar::Emotion::Happy, true};
        case AgentQMessageKind::rejected:
            return {
                lv_color_hex(0xF28B82), lv_color_hex(0x3C0505), stackchan::avatar::Emotion::Sad, false};
        case AgentQMessageKind::timeout:
            return {
                lv_color_hex(0xD0D5DD), lv_color_hex(0x2B2D33), stackchan::avatar::Emotion::Sleepy, false};
        case AgentQMessageKind::error:
            return {
                lv_color_hex(0xE25B5B), lv_color_hex(0xFFFFFF), stackchan::avatar::Emotion::Angry, false};
        case AgentQMessageKind::info:
        default:
            return {
                lv_color_hex(0x91D8FF), lv_color_hex(0x05324A), stackchan::avatar::Emotion::Doubt, true};
    }
}

void clear_agent_q_avatar_ui()
{
    if (g_ui.speech_avatar == nullptr) {
        g_ui.speech_mode = AgentQUiMode::none;
        g_ui.speech_decorator_id = -1;
        g_ui.message_deadline = 0;
        return;
    }

    auto* speech_avatar = g_ui.speech_avatar;
    LvglLockGuard lock;
    if (GetStackChan().hasAvatar()) {
        auto& current_avatar = GetStackChan().avatar();
        if (&current_avatar == speech_avatar) {
            if (g_ui.speech_decorator_id >= 0) {
                current_avatar.removeDecorator(g_ui.speech_decorator_id);
            }
            if (g_ui.owns_emotion) {
                current_avatar.setEmotion(g_ui.previous_emotion);
            }
        } else {
            ESP_LOGI(kTag, "Agent-Q avatar owner changed; dropping stale UI owner");
        }
    }
    g_ui.speech_avatar = nullptr;
    g_ui.speech_decorator_id = -1;
    g_ui.speech_mode = AgentQUiMode::none;
    g_ui.owns_emotion = false;
    g_ui.message_deadline = 0;
}

bool show_agent_q_message(
    const char* message,
    AgentQMessageKind kind,
    AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback = nullptr)
{
    clear_agent_q_avatar_ui();
    const AgentQMessagePresentation presentation = agent_q_message_presentation(kind);

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    if (!GetStackChan().hasAvatar()) {
        return false;
    }
    auto& avatar = GetStackChan().avatar();
    g_ui.previous_emotion = avatar.getEmotion();
    g_ui.owns_emotion = true;
    avatar.setEmotion(presentation.emotion);
    g_ui.speech_decorator_id = avatar.addDecorator(std::make_unique<agent_q::AgentQSpeechBubbleDecorator>(
        lv_screen_active(),
        message != nullptr && message[0] != '\0' ? message : "Agent-Q",
        presentation.background,
        presentation.foreground,
        click_callback));
    if (presentation.lift_head) {
        trigger_agent_q_head_lift();
    }
    g_ui.speech_avatar = &avatar;
    g_ui.speech_mode = mode;
    g_ui.message_deadline = duration_ms > 0 ? xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms) : 0;
    return g_ui.speech_decorator_id >= 0;
}

bool provisioning_welcome_available()
{
    bool ui_display_idle = false;
    {
        LvglLockGuard lock;
        ui_display_idle = g_ui.panel == nullptr && g_ui.speech_mode == AgentQUiMode::none;
    }

    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !g_root_material_consistency_error &&
           !g_pending.active &&
           !g_identification.active &&
           !recovery_phrase_flow_active() &&
           ui_display_idle;
}

void show_provisioning_welcome_if_available()
{
    if (!provisioning_welcome_available()) {
        return;
    }

    show_agent_q_message(
        "Set up Agent-Q", AgentQMessageKind::info, AgentQUiMode::identification, 0, on_setup_clicked);
}

void clear_agent_q_panel()
{
    LvglLockGuard lock;
    clear_panel_locked();
}

void clear_agent_q_request_ui()
{
    clear_agent_q_avatar_ui();
    clear_agent_q_panel();
}

void show_top_decision_panel()
{
    g_identification.clear();

    {
        LvglLockGuard lock;
        clear_panel_locked();

        g_ui.panel = lv_obj_create(lv_screen_active());
        register_agent_q_panel_locked(AgentQUiPanelKind::top_decision);
        lv_obj_remove_style_all(g_ui.panel);
        lv_obj_set_size(g_ui.panel, kScreenWidth, kTopDecisionPanelHeight);
        lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 0);
        lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
        lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
        lv_obj_set_style_radius(g_ui.panel, kTopDecisionCornerRadius, 0);
        lv_obj_set_style_clip_corner(g_ui.panel, true, 0);
        lv_obj_set_style_border_width(g_ui.panel, 0, 0);
        lv_obj_set_style_outline_width(g_ui.panel, 0, 0);
        lv_obj_set_style_shadow_width(g_ui.panel, 0, 0);
        lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_TRANSP, 0);
        lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

        make_top_decision_button(g_ui.panel, "Cancel", 0, lv_color_hex(0xA53B3B), on_no_clicked);
        make_top_decision_button(g_ui.panel, "Confirm", kTopDecisionButtonWidth, lv_color_hex(0x24875A), on_yes_clicked);

        lv_obj_move_foreground(g_ui.panel);
    }
}

void show_identification_code(const char* code, uint32_t duration_ms)
{
    clear_agent_q_request_ui();
    g_identification.begin(code, duration_ms);

    char message[40];
    snprintf(message, sizeof(message), "Device code: %s", code);
    if (!show_agent_q_message(message, AgentQMessageKind::info, AgentQUiMode::identification, duration_ms)) {
        ESP_LOGW(kTag, "identify_device could not show Agent-Q speech bubble");
    }
}

void clear_identification_if_needed()
{
    if (!g_identification.active || g_identification.deadline == 0 ||
        !tick_reached(g_identification.deadline)) {
        return;
    }

    clear_agent_q_request_ui();
    g_identification.clear();
    show_provisioning_welcome_if_available();
}

void clear_agent_q_message_if_needed()
{
    if (g_ui.message_deadline == 0 || !tick_reached(g_ui.message_deadline)) {
        return;
    }
    clear_agent_q_avatar_ui();
    show_provisioning_welcome_if_available();
}

bool show_avatar_decision(const char* message)
{
    if (!show_agent_q_message(message, AgentQMessageKind::approval, AgentQUiMode::decision, 0)) {
        return false;
    }
    show_top_decision_panel();
    return true;
}

void clear_pending_state()
{
    g_pending.clear();
    g_identification.clear();
}

void show_result_and_clear_pending(const char* message, AgentQMessageKind kind)
{
    clear_agent_q_panel();
    show_agent_q_message(message, kind, AgentQUiMode::result, kAgentQResultDisplayMs);
    clear_pending_state();
}

void show_display_signal_decision(const char* message)
{
    if (show_avatar_decision(message)) {
        return;
    }
    ESP_LOGW(kTag, "display_signal could not show Agent-Q avatar decision UI");
}

void format_connect_message(const char* gateway_name, char* output, size_t output_size)
{
    if (gateway_name == nullptr || gateway_name[0] == '\0') {
        gateway_name = "Agent-Q Gateway";
    }
    snprintf(output, output_size, "Connect %s?", gateway_name);
}

void show_connect_decision(const char* gateway_name)
{
    char message[kConnectDisplayMessageSize];
    format_connect_message(gateway_name, message, sizeof(message));
    if (show_avatar_decision(message)) {
        return;
    }
    ESP_LOGW(kTag, "connect could not show Agent-Q avatar decision UI");
}

void show_start_provisioning_decision()
{
    if (show_avatar_decision("Generate phrase?")) {
        return;
    }
    ESP_LOGW(kTag, "start_provisioning could not show Agent-Q avatar decision UI");
}

void show_cancel_provisioning_decision()
{
    if (show_avatar_decision("Cancel setup?")) {
        return;
    }
    ESP_LOGW(kTag, "cancel_provisioning could not show Agent-Q avatar decision UI");
}

void show_confirm_recovery_phrase_backup_decision()
{
    if (show_avatar_decision("Backup complete?")) {
        return;
    }
    ESP_LOGW(kTag, "confirm_recovery_phrase_backup could not show Agent-Q avatar decision UI");
}

void show_factory_reset_decision()
{
    if (show_avatar_decision("Wipe device?")) {
        return;
    }
    ESP_LOGW(kTag, "factory_reset could not show Agent-Q avatar decision UI");
}

bool show_recovery_phrase_display(const char* recovery_phrase)
{
    if (!format_recovery_phrase_prefix_cells(
            recovery_phrase, g_provisioning_scratch.recovery_phrase_prefix_cells)) {
        return false;
    }

    clear_agent_q_request_ui();

    LvglLockGuard lock;
    clear_panel_locked();

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::recovery_phrase_display);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 28);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 14);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 2, 0);
    lv_obj_set_style_border_color(g_ui.panel, lv_color_hex(0x24875A), 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 10, 0);

    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "BIP-39 prefixes (DEV)");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t* warning = lv_label_create(g_ui.panel);
    if (warning == nullptr) {
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(warning, "Write up-to-4-letter prefixes. Host cannot read them.");
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, kScreenWidth - 44);
    lv_obj_set_style_text_align(warning, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(warning, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(warning, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(warning, LV_ALIGN_TOP_MID, 0, 22);

    constexpr int kGridLeft = 12;
    constexpr int kGridTop = 64;
    constexpr int kGridCellWidth = 90;
    constexpr int kGridCellHeight = 22;
    constexpr int kGridRowHeight = 25;
    constexpr int kIndexWidth = 22;
    constexpr int kPrefixLeft = 30;
    constexpr int kPrefixWidth = 54;
    for (size_t index = 0; index < kRecoveryPhrasePrefixCellCount; ++index) {
        lv_obj_t* cell = lv_obj_create(g_ui.panel);
        if (cell == nullptr) {
            clear_panel_locked();
            return false;
        }
        lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(cell, kGridCellWidth, kGridCellHeight);
        lv_obj_set_style_radius(cell, 4, 0);
        lv_obj_set_style_border_width(cell, 1, 0);
        lv_obj_set_style_border_color(cell, lv_color_hex(0xB7E4C7), 0);
        lv_obj_set_style_bg_color(cell, lv_color_hex(0xFFFFFF), 0);
        lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
        lv_obj_set_style_pad_all(cell, 0, 0);
        const int column = static_cast<int>(index % 3);
        const int row = static_cast<int>(index / 3);
        lv_obj_align(
            cell,
            LV_ALIGN_TOP_LEFT,
            kGridLeft + column * kGridCellWidth,
            kGridTop + row * kGridRowHeight);

        lv_obj_t* index_label = lv_label_create(cell);
        if (index_label == nullptr) {
            clear_panel_locked();
            return false;
        }
        char index_text[3] = {};
        snprintf(index_text, sizeof(index_text), "%02u", static_cast<unsigned>(index + 1));
        lv_label_set_text(index_label, index_text);
        lv_label_set_long_mode(index_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(index_label, kIndexWidth);
        lv_obj_set_style_text_align(index_label, LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_set_style_text_font(index_label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(index_label, lv_color_hex(0x475467), 0);
        lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);

        lv_obj_t* prefix_label = lv_label_create(cell);
        if (prefix_label == nullptr) {
            clear_panel_locked();
            return false;
        }
        lv_label_set_text_static(prefix_label, g_provisioning_scratch.recovery_phrase_prefix_cells[index]);
        lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(prefix_label, kPrefixWidth);
        lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
        lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(prefix_label, lv_color_hex(0x111827), 0);
        lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kPrefixLeft, 0);
    }
    lv_obj_t* footer = lv_label_create(g_ui.panel);
    if (footer == nullptr) {
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(footer, "Confirm backup from setup.");
    lv_obj_set_style_text_font(footer, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(footer, lv_color_hex(0x475467), 0);
    lv_obj_align(footer, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_move_foreground(g_ui.panel);
    return true;
}

RecoveryPhraseGenerationResult generate_recovery_phrase_scratch()
{
    wipe_recovery_phrase_scratch("recovery phrase generation reset");

    if (!agent_q::fill_secure_random(
            g_provisioning_scratch.root_material,
            sizeof(g_provisioning_scratch.root_material))) {
        wipe_recovery_phrase_scratch("recovery phrase entropy failure");
        return RecoveryPhraseGenerationResult::rng_error;
    }
    const bool generated = agent_q::make_bip39_mnemonic_12_words(
        g_provisioning_scratch.root_material,
        g_provisioning_scratch.recovery_phrase,
        sizeof(g_provisioning_scratch.recovery_phrase));
    if (!generated) {
        wipe_recovery_phrase_scratch("recovery phrase generation failure");
        return RecoveryPhraseGenerationResult::generation_error;
    }

    g_provisioning_scratch.recovery_phrase_stage = RecoveryPhraseScratchStage::displayed;
    g_provisioning_scratch.recovery_phrase_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kRecoveryPhraseDisplayMs);
    return RecoveryPhraseGenerationResult::ok;
}

void clear_recovery_phrase_if_needed()
{
    if (g_provisioning_scratch.recovery_phrase_stage != RecoveryPhraseScratchStage::displayed) {
        return;
    }

    const bool panel_active = recovery_phrase_display_panel_active();
    const bool expired = g_provisioning_scratch.recovery_phrase_deadline != 0 &&
                         tick_reached(g_provisioning_scratch.recovery_phrase_deadline);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_recovery_phrase_scratch("recovery phrase display lost");
    }

    if (expired) {
        show_agent_q_message("Phrase expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void poll_touch_fallback()
{
    if (!g_pending.awaiting_choice()) {
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    if (touch.num == 0) {
        g_pending.touch_armed = true;
        return;
    }
    if (!g_pending.touch_armed) {
        return;
    }

    lv_area_t panel_area;
    {
        LvglLockGuard lock;
        if (g_ui.panel == nullptr || !is_decision_panel_kind(g_ui.panel_kind)) {
            return;
        }
        lv_obj_get_coords(g_ui.panel, &panel_area);
    }

    const int panel_width = panel_area.x2 - panel_area.x1 + 1;
    const int panel_height = panel_area.y2 - panel_area.y1 + 1;
    const int relative_x = touch.x - panel_area.x1;
    const int relative_y = touch.y - panel_area.y1;
    const bool inside_panel = relative_x >= 0 && relative_y >= 0 &&
                              relative_x < panel_width && relative_y < panel_height;
    if (!inside_panel) {
        return;
    }

    g_pending.choice = relative_x < panel_width / 2 ? PendingChoice::no : PendingChoice::yes;
    g_pending.touch_armed = false;
}

void drain_pending_choice_events()
{
    if (g_pending_choice_queue == nullptr) {
        return;
    }

    PendingChoice choice = PendingChoice::none;
    while (xQueueReceive(g_pending_choice_queue, &choice, 0) == pdTRUE) {
        if (g_pending.awaiting_choice()) {
            g_pending.choice = choice;
            g_pending.touch_armed = false;
        }
    }
}

void start_local_provisioning_from_setup_touch()
{
    if (!provisioning_transition_allowed(PendingKind::start_provisioning)) {
        ESP_LOGW(kTag, "Local setup touch ignored because setup is unavailable");
        clear_agent_q_request_ui();
        show_agent_q_message("Setup unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    clear_agent_q_request_ui();
    const RecoveryPhraseGenerationResult generation_result = generate_recovery_phrase_scratch();
    if (generation_result == RecoveryPhraseGenerationResult::ok) {
        if (show_recovery_phrase_display(g_provisioning_scratch.recovery_phrase)) {
            ESP_LOGI(kTag, "Local setup recovery phrase displayed");
        } else {
            wipe_recovery_phrase_scratch("local setup recovery phrase display allocation failed");
            ESP_LOGW(kTag, "Local setup display failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (generation_result == RecoveryPhraseGenerationResult::rng_error) {
        ESP_LOGW(kTag, "Local setup RNG failed");
        show_agent_q_message("RNG error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    ESP_LOGW(kTag, "Local setup phrase generation failed");
    show_agent_q_message("Generation error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
}

void drain_ui_events()
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent event;
    while (xQueueReceive(g_ui_event_queue, &event, 0) == pdTRUE) {
        if (event.kind == AgentQUiEventKind::setup_requested) {
            start_local_provisioning_from_setup_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::provisioning_welcome_requested) {
            show_provisioning_welcome_if_available();
            continue;
        }

        if (event.kind != AgentQUiEventKind::panel_deleted) {
            continue;
        }
        if (event.panel_kind == AgentQUiPanelKind::recovery_phrase_display &&
            g_provisioning_scratch.recovery_phrase_stage == RecoveryPhraseScratchStage::displayed) {
            wipe_recovery_phrase_scratch("recovery phrase panel deleted");
        }
    }
}

void ensure_pending_request_ui()
{
    if (!g_pending.awaiting_choice()) {
        return;
    }

    bool needs_decision_panel = false;
    {
        LvglLockGuard lock;
        needs_decision_panel = g_ui.panel == nullptr || !is_decision_panel_kind(g_ui.panel_kind);
    }
    if (!needs_decision_panel) {
        return;
    }

    switch (g_pending.kind) {
        case PendingKind::display_signal:
            show_display_signal_decision(g_pending.display_message);
            ESP_LOGW(kTag, "display_signal decision UI recovered: id=%s", g_pending.id);
            break;
        case PendingKind::connect:
            show_connect_decision(g_pending.gateway_name);
            ESP_LOGW(kTag, "connect decision UI recovered: id=%s", g_pending.id);
            break;
        case PendingKind::factory_reset:
            show_factory_reset_decision();
            ESP_LOGW(kTag, "factory_reset decision UI recovered: id=%s", g_pending.id);
            break;
        case PendingKind::start_provisioning:
            show_start_provisioning_decision();
            ESP_LOGW(kTag, "start_provisioning decision UI recovered: id=%s", g_pending.id);
            break;
        case PendingKind::cancel_provisioning:
            show_cancel_provisioning_decision();
            ESP_LOGW(kTag, "cancel_provisioning decision UI recovered: id=%s", g_pending.id);
            break;
        case PendingKind::confirm_recovery_phrase_backup:
            show_confirm_recovery_phrase_backup_decision();
            ESP_LOGW(kTag, "confirm_recovery_phrase_backup decision UI recovered: id=%s", g_pending.id);
            break;
        case PendingKind::none:
            break;
    }
}

void send_choice_response_if_needed()
{
    drain_pending_choice_events();
    poll_touch_fallback();

    if (!g_pending.active || g_pending.choice == PendingChoice::none) {
        if (g_pending.active && g_pending.deadline != 0 &&
            tick_reached(g_pending.deadline)) {
            // Device leaves awaiting_approval before reporting the result.
            g_pending.active = false;
            switch (g_pending.kind) {
                case PendingKind::display_signal:
                    write_display_signal_result(g_pending.id, "rejected", "timeout", "Request timed out.");
                    ESP_LOGI(kTag, "display_signal timed out: id=%s", g_pending.id);
                    show_result_and_clear_pending("Timed out", AgentQMessageKind::timeout);
                    break;
                case PendingKind::connect:
                    write_connect_rejected_response(g_pending.id, "timeout", "Connection approval timed out.");
                    ESP_LOGI(kTag, "connect timed out: id=%s", g_pending.id);
                    show_result_and_clear_pending("Connection timed out", AgentQMessageKind::timeout);
                    break;
                case PendingKind::factory_reset:
                    write_error_response(g_pending.id, "timeout", "Factory reset approval timed out.");
                    ESP_LOGI(kTag, "factory_reset timed out: id=%s", g_pending.id);
                    show_result_and_clear_pending("Reset timed out", AgentQMessageKind::timeout);
                    break;
                case PendingKind::start_provisioning:
                    write_error_response(g_pending.id, "timeout", "Provisioning start approval timed out.");
                    ESP_LOGI(kTag, "start_provisioning timed out: id=%s", g_pending.id);
                    show_result_and_clear_pending("Setup timed out", AgentQMessageKind::timeout);
                    break;
                case PendingKind::cancel_provisioning:
                    wipe_recovery_phrase_scratch("cancel_provisioning timeout");
                    write_error_response(g_pending.id, "timeout", "Provisioning cancellation timed out.");
                    ESP_LOGI(kTag, "cancel_provisioning timed out: id=%s", g_pending.id);
                    show_result_and_clear_pending("Cancel timed out", AgentQMessageKind::timeout);
                    break;
                case PendingKind::confirm_recovery_phrase_backup:
                    wipe_recovery_phrase_scratch("confirm_recovery_phrase_backup timeout");
                    write_error_response(g_pending.id, "timeout", "Recovery phrase backup confirmation timed out.");
                    ESP_LOGI(kTag, "confirm_recovery_phrase_backup timed out: id=%s", g_pending.id);
                    show_result_and_clear_pending("Backup timed out", AgentQMessageKind::timeout);
                    break;
                case PendingKind::none:
                    clear_pending_state();
                    break;
            }
        }
        return;
    }

    const bool approved = g_pending.choice == PendingChoice::yes;
    g_pending.active = false;
    switch (g_pending.kind) {
        case PendingKind::display_signal:
            write_display_signal_result(g_pending.id, approved ? "approved" : "rejected", nullptr, nullptr);
            ESP_LOGI(kTag, "display_signal %s: id=%s", approved ? "approved" : "rejected", g_pending.id);
            show_result_and_clear_pending(approved ? "Approved" : "Rejected",
                                          approved ? AgentQMessageKind::success : AgentQMessageKind::rejected);
            break;
        case PendingKind::connect:
            if (approved) {
                if (!replace_active_session()) {
                    write_error_response(g_pending.id, "rng_error", "Could not create session id.");
                    ESP_LOGE(kTag, "connect could not create session id: id=%s", g_pending.id);
                    show_result_and_clear_pending("RNG error", AgentQMessageKind::error);
                    break;
                }
                write_connect_approved_response(g_pending.id);
                ESP_LOGI(kTag, "connect approved: id=%s", g_pending.id);
                show_result_and_clear_pending("Connected", AgentQMessageKind::success);
            } else {
                write_connect_rejected_response(g_pending.id, "rejected", "Connection rejected.");
                ESP_LOGI(kTag, "connect rejected: id=%s", g_pending.id);
                show_result_and_clear_pending("Connection rejected", AgentQMessageKind::rejected);
            }
            break;
        case PendingKind::factory_reset:
            if (approved) {
                if (reset_device_to_unprovisioned()) {
                    write_factory_reset_result(g_pending.id);
                    ESP_LOGI(kTag, "factory_reset approved: id=%s", g_pending.id);
                    show_result_and_clear_pending("Device wiped", AgentQMessageKind::success);
                } else {
                    write_error_response(g_pending.id, "storage_error", "Could not reset device.");
                    ESP_LOGW(kTag, "factory_reset storage error: id=%s", g_pending.id);
                    show_result_and_clear_pending("Reset error", AgentQMessageKind::error);
                }
            } else {
                write_error_response(g_pending.id, "rejected", "Factory reset rejected.");
                ESP_LOGI(kTag, "factory_reset rejected: id=%s", g_pending.id);
                show_result_and_clear_pending("Reset rejected", AgentQMessageKind::rejected);
            }
            break;
        case PendingKind::start_provisioning:
            if (approved) {
                clear_agent_q_request_ui();
                const RecoveryPhraseGenerationResult generation_result = generate_recovery_phrase_scratch();
                if (generation_result == RecoveryPhraseGenerationResult::ok) {
                    if (show_recovery_phrase_display(g_provisioning_scratch.recovery_phrase)) {
                        write_recovery_phrase_result(g_pending.id, "displayed");
                        ESP_LOGI(kTag, "start_provisioning approved and recovery phrase displayed: id=%s", g_pending.id);
                        clear_pending_state();
                    } else {
                        wipe_recovery_phrase_scratch("recovery phrase display allocation failed");
                        write_error_response(g_pending.id, "ui_error", "Could not display recovery phrase.");
                        ESP_LOGW(kTag, "start_provisioning display failed: id=%s", g_pending.id);
                        show_result_and_clear_pending("Display error", AgentQMessageKind::error);
                    }
                } else if (generation_result == RecoveryPhraseGenerationResult::rng_error) {
                    write_error_response(g_pending.id, "rng_error", "Could not generate recovery phrase entropy.");
                    ESP_LOGW(kTag, "start_provisioning RNG failed: id=%s", g_pending.id);
                    show_result_and_clear_pending("RNG error", AgentQMessageKind::error);
                } else {
                    write_error_response(g_pending.id, "generation_error", "Could not generate recovery phrase.");
                    ESP_LOGW(kTag, "start_provisioning phrase generation failed: id=%s", g_pending.id);
                    show_result_and_clear_pending("Generation error", AgentQMessageKind::error);
                }
            } else {
                write_error_response(g_pending.id, "rejected", "Provisioning start rejected.");
                ESP_LOGI(kTag, "start_provisioning rejected: id=%s", g_pending.id);
                show_result_and_clear_pending("Setup rejected", AgentQMessageKind::rejected);
            }
            break;
        case PendingKind::cancel_provisioning:
            if (approved) {
                const bool must_persist_unprovisioned =
                    g_provisioning_state != ProvisioningRuntimeState::unprovisioned;
                if (wipe_provisioning_scratch_state() &&
                    (!must_persist_unprovisioned ||
                     persist_provisioning_state(ProvisioningRuntimeState::unprovisioned))) {
                    write_provisioning_result(g_pending.id, "canceled");
                    ESP_LOGI(kTag, "cancel_provisioning approved: id=%s", g_pending.id);
                    show_result_and_clear_pending("Setup canceled", AgentQMessageKind::success);
                } else {
                    write_error_response(g_pending.id, "storage_error", "Could not store provisioning state.");
                    ESP_LOGW(kTag, "cancel_provisioning storage error: id=%s", g_pending.id);
                    show_result_and_clear_pending("Storage error", AgentQMessageKind::error);
                }
            } else {
                wipe_recovery_phrase_scratch("cancel_provisioning rejected");
                write_error_response(g_pending.id, "rejected", "Provisioning cancellation rejected.");
                ESP_LOGI(kTag, "cancel_provisioning rejected: id=%s", g_pending.id);
                show_result_and_clear_pending("Cancel rejected", AgentQMessageKind::rejected);
            }
            break;
        case PendingKind::confirm_recovery_phrase_backup:
            if (approved) {
                if (g_provisioning_scratch.recovery_phrase_stage !=
                    RecoveryPhraseScratchStage::backup_confirmation_pending) {
                    write_error_response(
                        g_pending.id, "invalid_setup_step", "Recovery phrase is no longer available for backup confirmation.");
                    ESP_LOGW(kTag, "confirm_recovery_phrase_backup missing scratch: id=%s", g_pending.id);
                    show_result_and_clear_pending("Phrase unavailable", AgentQMessageKind::error);
                    break;
                }
                if (!agent_q::store_root_material(
                        g_provisioning_scratch.root_material,
                        sizeof(g_provisioning_scratch.root_material))) {
                    g_root_material_consistency_error = agent_q::has_root_material();
                    wipe_recovery_phrase_scratch("confirm_recovery_phrase_backup storage failed");
                    write_error_response(g_pending.id, "storage_error", "Could not store root material.");
                    ESP_LOGW(kTag, "confirm_recovery_phrase_backup root material storage failed: id=%s", g_pending.id);
                    show_result_and_clear_pending("Storage error", AgentQMessageKind::error);
                    break;
                }
                if (!persist_provisioning_state(ProvisioningRuntimeState::provisioned)) {
                    agent_q::wipe_root_material();
                    g_root_material_consistency_error = agent_q::has_root_material();
                    wipe_recovery_phrase_scratch("confirm_recovery_phrase_backup state storage failed");
                    write_error_response(g_pending.id, "storage_error", "Could not store provisioned state.");
                    ESP_LOGW(kTag, "confirm_recovery_phrase_backup provisioned state storage failed: id=%s", g_pending.id);
                    show_result_and_clear_pending("Storage error", AgentQMessageKind::error);
                    break;
                }
                g_root_material_consistency_error = false;
                wipe_recovery_phrase_scratch("confirm_recovery_phrase_backup approved");
                write_recovery_phrase_result(g_pending.id, "confirmed");
                ESP_LOGI(kTag, "confirm_recovery_phrase_backup approved and provisioned: id=%s", g_pending.id);
                show_result_and_clear_pending("Provisioned", AgentQMessageKind::success);
            } else {
                wipe_recovery_phrase_scratch("confirm_recovery_phrase_backup rejected");
                write_error_response(g_pending.id, "rejected", "Recovery phrase backup confirmation rejected.");
                ESP_LOGI(kTag, "confirm_recovery_phrase_backup rejected: id=%s", g_pending.id);
                show_result_and_clear_pending("Backup rejected", AgentQMessageKind::rejected);
            }
            break;
        case PendingKind::none:
            clear_pending_state();
            break;
    }
}

void handle_line(const char* line)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, line);
    if (error) {
        write_error_response(nullptr, "invalid_json", "Invalid JSON.");
        return;
    }

    const char* id = request["id"] | "";
    if (!is_safe_id(id)) {
        write_error_response(nullptr, "invalid_id", "Invalid request id.");
        return;
    }

    const int version = request["version"] | 0;
    if (version != kProtocolVersion) {
        write_error_response(id, "unsupported_version", "Unsupported protocol version.");
        return;
    }

    const char* type = request["type"] | "";
    if (strcmp(type, "get_status") == 0) {
        write_status_response(id);
        return;
    }

    if (strcmp(type, "identify_device") == 0) {
        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }
        if (recovery_phrase_flow_active()) {
            write_error_response(id, "busy", "Device is showing setup material.");
            return;
        }

        const char* code = request["params"]["code"] | "";
        if (!is_safe_identification_code(code)) {
            write_error_response(id, "invalid_code", "Invalid identification code.");
            return;
        }

        const uint32_t duration_ms = request["params"]["durationMs"] | kIdentifyDisplayDefaultMs;
        if (duration_ms == 0 || duration_ms > kIdentifyDisplayMaxMs) {
            write_error_response(id, "invalid_duration", "Invalid identification duration.");
            return;
        }

        show_identification_code(code, duration_ms);
        write_identify_device_result(id, code);
        ESP_LOGI(kTag, "identify_device displayed: id=%s code=%s", id, code);
        return;
    }

    if (strcmp(type, "connect") == 0) {
        if (g_provisioning_state != ProvisioningRuntimeState::provisioned ||
            g_root_material_consistency_error) {
            write_error_response(id, "invalid_state", "Connect is available only after provisioning is complete.");
            return;
        }
        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }
        if (recovery_phrase_flow_active()) {
            write_error_response(id, "busy", "Device is showing setup material.");
            return;
        }

        const char* gateway_name = request["params"]["gatewayName"] | "";
        if (!is_printable_ascii_gateway_name(gateway_name)) {
            write_error_response(id, "invalid_gateway_name", "gatewayName must be 1-64 printable ASCII characters.");
            return;
        }

        uint32_t approval_timeout_ms = request["params"]["approvalTimeoutMs"] | kConnectApprovalDefaultMs;
        if (approval_timeout_ms == 0 || approval_timeout_ms > kConnectApprovalMaxMs) {
            write_error_response(id, "invalid_approval_timeout", "Invalid approval timeout.");
            return;
        }

        g_pending.begin_connect(id, gateway_name, approval_timeout_ms);
        show_connect_decision(g_pending.gateway_name);
        ESP_LOGI(kTag, "connect waiting for YES/NO: id=%s gateway=%s", id, g_pending.gateway_name);
        return;
    }

    if (strcmp(type, "disconnect") == 0) {
        if (g_provisioning_state != ProvisioningRuntimeState::provisioned ||
            g_root_material_consistency_error) {
            write_error_response(id, "invalid_state", "Disconnect is available only after provisioning is complete.");
            return;
        }
        // disconnect is session-changing; reject it while an approval UI is
        // active or setup material is displayed so it cannot mutate session
        // state mid-approval or while device-only setup material is visible.
        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }
        if (recovery_phrase_display_active()) {
            write_error_response(id, "busy", "Device is showing setup material.");
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!is_safe_session_id(session_id)) {
            write_error_response(id, "invalid_session", "Invalid sessionId.");
            return;
        }
        if (!g_session.active()) {
            clear_active_session();
            write_error_response(id, "invalid_session", "Session is unknown or already ended.");
            return;
        }
        if (tick_reached(g_session.expiry)) {
            clear_active_session();
            write_error_response(id, "invalid_session", "Session is unknown or already ended.");
            return;
        }
        if (strcmp(session_id, g_session.id) != 0) {
            write_error_response(id, "invalid_session", "Session is unknown or already ended.");
            return;
        }
        clear_active_session();
        write_disconnect_result(id);
        ESP_LOGI(kTag, "disconnect: id=%s", id);
        return;
    }

    if (strcmp(type, "factory_reset") == 0) {
        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }
        if (recovery_phrase_flow_active()) {
            write_error_response(id, "busy", "Device is showing setup material.");
            return;
        }

        uint32_t approval_timeout_ms = request["params"]["approvalTimeoutMs"] | kProvisioningApprovalDefaultMs;
        if (approval_timeout_ms == 0 || approval_timeout_ms > kProvisioningApprovalMaxMs) {
            write_error_response(id, "invalid_approval_timeout", "Invalid approval timeout.");
            return;
        }

        g_pending.begin_factory_reset(id, approval_timeout_ms);
        show_factory_reset_decision();
        ESP_LOGI(kTag, "factory_reset waiting for YES/NO: id=%s", id);
        return;
    }

    if (strcmp(type, "start_provisioning") == 0 || strcmp(type, "cancel_provisioning") == 0) {
        const PendingKind request_kind = strcmp(type, "start_provisioning") == 0
            ? PendingKind::start_provisioning
            : PendingKind::cancel_provisioning;
        if (request_kind == PendingKind::start_provisioning && start_provisioning_busy()) {
            write_error_response(id, "busy", "Recovery phrase setup is already active.");
            return;
        }
        if (!provisioning_transition_allowed(request_kind)) {
            write_invalid_provisioning_state_response(id, request_kind);
            return;
        }

        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }

        uint32_t approval_timeout_ms = request["params"]["approvalTimeoutMs"] | kProvisioningApprovalDefaultMs;
        if (approval_timeout_ms == 0 || approval_timeout_ms > kProvisioningApprovalMaxMs) {
            write_error_response(id, "invalid_approval_timeout", "Invalid approval timeout.");
            return;
        }

        if (request_kind == PendingKind::start_provisioning) {
            g_pending.begin_provisioning_transition(id, request_kind, approval_timeout_ms);
            show_start_provisioning_decision();
            ESP_LOGI(kTag, "start_provisioning waiting for YES/NO: id=%s", id);
            return;
        }

        g_pending.begin_provisioning_transition(id, request_kind, approval_timeout_ms);
        show_cancel_provisioning_decision();
        ESP_LOGI(kTag, "cancel_provisioning waiting for YES/NO: id=%s", id);
        return;
    }

    if (strcmp(type, "confirm_recovery_phrase_backup") == 0) {
        if (g_provisioning_state != ProvisioningRuntimeState::unprovisioned) {
            write_invalid_recovery_phrase_state_response(id);
            return;
        }

        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }

        if (!recovery_phrase_backup_confirmation_ready()) {
            write_recovery_phrase_not_ready_response(id);
            return;
        }

        uint32_t approval_timeout_ms = request["params"]["approvalTimeoutMs"] | kProvisioningApprovalDefaultMs;
        if (approval_timeout_ms == 0 || approval_timeout_ms > kProvisioningApprovalMaxMs) {
            write_error_response(id, "invalid_approval_timeout", "Invalid approval timeout.");
            return;
        }

        // The LVGL task can delete the phrase display while this USB task is
        // validating parameters, so readiness is checked again before the
        // scratch state moves to backup_confirmation_pending.
        if (!recovery_phrase_backup_confirmation_ready()) {
            write_recovery_phrase_not_ready_response(id);
            return;
        }

        g_pending.begin_recovery_phrase_step(
            id, PendingKind::confirm_recovery_phrase_backup, approval_timeout_ms);
        g_provisioning_scratch.recovery_phrase_stage =
            RecoveryPhraseScratchStage::backup_confirmation_pending;
        show_confirm_recovery_phrase_backup_decision();
        ESP_LOGI(kTag, "confirm_recovery_phrase_backup waiting for YES/NO: id=%s", id);
        return;
    }

    if (strcmp(type, "display_signal") != 0) {
        write_error_response(id, "unsupported_type", "Unsupported request type.");
        return;
    }

    if (g_pending.active) {
        write_error_response(id, "busy", "Device is awaiting physical input.");
        return;
    }
    if (recovery_phrase_display_active()) {
        write_error_response(id, "busy", "Device is showing setup material.");
        return;
    }

    const char* message = request["params"]["message"] | "USB request";
    g_pending.begin_display_signal(id, message);
    show_display_signal_decision(g_pending.display_message);
    ESP_LOGI(kTag, "display_signal waiting for YES/NO: id=%s", id);
}

void poll_usb_input()
{
    uint8_t buffer[64];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }

    for (int index = 0; index < read_count; ++index) {
        const char c = static_cast<char>(buffer[index]);
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            g_line_buffer[g_line_size] = '\0';
            if (g_line_size > 0) {
                handle_line(g_line_buffer);
            }
            g_line_size = 0;
            continue;
        }

        if (g_line_size + 1 >= sizeof(g_line_buffer)) {
            g_line_size = 0;
            write_error_response(nullptr, "invalid_json", "JSON line is too long.");
            continue;
        }

        g_line_buffer[g_line_size++] = c;
    }
}

void usb_request_task(void*)
{
    // Ordering matters: any pending YES/NO choice is resolved and its response is
    // sent (send_choice_response_if_needed) before new input is read
    // (poll_usb_input). A new request therefore cannot be handled until the
    // in-flight approval response has been written in the same loop pass.
    while (true) {
        drain_ui_events();
        clear_identification_if_needed();
        clear_agent_q_message_if_needed();
        clear_recovery_phrase_if_needed();
        expire_session_if_needed();
        send_choice_response_if_needed();
        ensure_pending_request_ui();
        if (g_usb_ready) {
            poll_usb_input();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

}  // namespace

namespace agent_q {

void init_usb_request_server()
{
    load_or_create_device_id();
    load_provisioning_state();
    g_session.clear();
    g_session.next_expiry_check = 0;
    g_pending.clear();
    g_identification.clear();
    wipe_recovery_phrase_scratch("usb request server init");
    if (g_pending_choice_queue == nullptr) {
        g_pending_choice_queue = xQueueCreate(4, sizeof(PendingChoice));
        if (g_pending_choice_queue == nullptr) {
            ESP_LOGE(kTag, "Pending choice queue create failed");
        }
    } else {
        xQueueReset(g_pending_choice_queue);
    }
    if (g_ui_event_queue == nullptr) {
        g_ui_event_queue = xQueueCreate(4, sizeof(AgentQUiEvent));
        if (g_ui_event_queue == nullptr) {
            ESP_LOGE(kTag, "UI event queue create failed");
        }
    } else {
        xQueueReset(g_ui_event_queue);
    }
    g_ui = AgentQUiState{};

    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 1024;
        config.rx_buffer_size = 1024;
        const esp_err_t result = usb_serial_jtag_driver_install(&config);
        if (result != ESP_OK) {
            ESP_LOGE(kTag, "USB serial driver install failed: %s", esp_err_to_name(result));
            return;
        }
    }

    g_usb_ready = true;
    if (g_usb_task == nullptr) {
        BaseType_t task_created = xTaskCreatePinnedToCore(
            usb_request_task, "agent_q_usb", 4096, nullptr, 4, &g_usb_task, 1);
        if (task_created != pdPASS) {
            ESP_LOGE(kTag, "USB request task start failed");
            g_usb_ready = false;
            g_usb_task = nullptr;
            return;
        }
    }
    ESP_LOGI(kTag, "USB request server ready");
}

void show_provisioning_welcome_if_needed()
{
    enqueue_provisioning_welcome_requested();
}

}  // namespace agent_q
