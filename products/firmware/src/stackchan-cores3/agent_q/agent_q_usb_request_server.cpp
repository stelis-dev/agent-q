#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_speech_bubble.h"
#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
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
constexpr uint32_t kDisplaySignalTimeoutMs = 30000;
constexpr uint32_t kIdentifyDisplayDefaultMs = 10000;
constexpr uint32_t kIdentifyDisplayMaxMs = 30000;
constexpr uint32_t kConnectApprovalDefaultMs = 30000;
constexpr uint32_t kConnectApprovalMaxMs = 60000;
// Session lifetime advertised to Gateway. 30 minutes is a convenience value for
// the connection session, which grants no signing authority. When signing
// methods are added, reconsider and likely shorten this.
constexpr uint32_t kSessionTtlMs = 1800000;
// Sessions are checked for expiry on a coarse interval, not every task tick: a
// single 30-minute session does not need millisecond-accurate eviction.
constexpr uint32_t kSessionExpiryCheckMs = 5000;
constexpr size_t kLineBufferSize = 512;
constexpr size_t kResponseBufferSize = 512;
constexpr size_t kMaxRequestIdSize = 80;
constexpr size_t kDeviceIdSize = 37;
constexpr size_t kIdentifyCodeSize = 5;
constexpr size_t kSessionIdSize = 26;
constexpr size_t kGatewayNameSize = 65;
constexpr size_t kConnectDisplayMessageSize = 96;
constexpr size_t kPendingDisplayMessageSize = kLineBufferSize;
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

enum class PendingKind {
    none,
    display_signal,
    connect,
};

// Firmware-owned state is kept separate from StackChan-owned avatar/app state.
// Agent-Q records protocol/session/UI ownership here and only stores StackChan
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

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
char g_device_id[kDeviceIdSize];
PendingApprovalState g_pending;
IdentificationState g_identification;
SessionState g_session;
AgentQUiState g_ui;
bool g_usb_ready = false;
TaskHandle_t g_usb_task = nullptr;

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
    if (g_pending.active) {
        return "awaiting_approval";
    }
    return "idle";
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
    response["provisioning"]["state"] = "unprovisioned";
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
    response["device"]["state"] = current_device_state();
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

void format_session_id(char* output, size_t output_size)
{
    uint8_t bytes[8];
    esp_fill_random(bytes, sizeof(bytes));
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
}

void clear_active_session()
{
    g_session.clear();
}

void replace_active_session()
{
    format_session_id(g_session.id, sizeof(g_session.id));
    g_session.expiry = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionTtlMs);
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

void format_uuid_v4(char* output, size_t output_size)
{
    uint8_t bytes[16];
    esp_fill_random(bytes, sizeof(bytes));
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
}

void load_or_create_device_id()
{
    g_device_id[0] = '\0';

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed for device id: %s", esp_err_to_name(result));
        format_uuid_v4(g_device_id, sizeof(g_device_id));
        return;
    }

    size_t length = sizeof(g_device_id);
    result = nvs_get_str(nvs, kDeviceIdKey, g_device_id, &length);
    if (result == ESP_OK && g_device_id[0] != '\0') {
        nvs_close(nvs);
        ESP_LOGI(kTag, "Loaded device id from NVS");
        return;
    }

    format_uuid_v4(g_device_id, sizeof(g_device_id));
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

void on_yes_clicked(lv_event_t*)
{
    if (g_pending.awaiting_choice()) {
        g_pending.choice = PendingChoice::yes;
    }
}

void on_no_clicked(lv_event_t*)
{
    if (g_pending.awaiting_choice()) {
        g_pending.choice = PendingChoice::no;
    }
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

bool should_lift_head_for_message(AgentQMessageKind kind)
{
    return kind == AgentQMessageKind::info || kind == AgentQMessageKind::approval ||
           kind == AgentQMessageKind::success;
}

void trigger_agent_q_head_lift()
{
    GetStackChan().addModifier(std::make_unique<AgentQHeadLiftModifier>());
}

void on_agent_q_panel_deleted(lv_event_t* event)
{
    lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_target(event));
    if (g_ui.panel == target) {
        if (g_pending.active) {
            ESP_LOGW(kTag, "Agent-Q decision panel was deleted by external UI state");
        }
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
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
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
        lv_obj_delete(panel);
    } else {
        g_ui.panel_kind = AgentQUiPanelKind::none;
    }
}

struct AgentQMessageStyle {
    lv_color_t background;
    lv_color_t foreground;
    stackchan::avatar::Emotion emotion;
};

AgentQMessageStyle message_style(AgentQMessageKind kind)
{
    switch (kind) {
        case AgentQMessageKind::approval:
            return {lv_color_hex(0xFFD166), lv_color_hex(0x3A2B00), stackchan::avatar::Emotion::Neutral};
        case AgentQMessageKind::success:
            return {lv_color_hex(0x7DE2A6), lv_color_hex(0x063A1D), stackchan::avatar::Emotion::Happy};
        case AgentQMessageKind::rejected:
            return {lv_color_hex(0xF28B82), lv_color_hex(0x3C0505), stackchan::avatar::Emotion::Sad};
        case AgentQMessageKind::timeout:
            return {lv_color_hex(0xD0D5DD), lv_color_hex(0x2B2D33), stackchan::avatar::Emotion::Sleepy};
        case AgentQMessageKind::error:
            return {lv_color_hex(0xE25B5B), lv_color_hex(0xFFFFFF), stackchan::avatar::Emotion::Angry};
        case AgentQMessageKind::info:
        default:
            return {lv_color_hex(0x91D8FF), lv_color_hex(0x05324A), stackchan::avatar::Emotion::Doubt};
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
                current_avatar.setModifyLock(false);
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

bool show_agent_q_message(const char* message, AgentQMessageKind kind, AgentQUiMode mode, uint32_t duration_ms)
{
    clear_agent_q_avatar_ui();
    const AgentQMessageStyle style = message_style(kind);

    LvglLockGuard lock;
    if (!GetStackChan().hasAvatar()) {
        return false;
    }
    auto& avatar = GetStackChan().avatar();
    g_ui.previous_emotion = avatar.getEmotion();
    g_ui.owns_emotion = true;
    avatar.setModifyLock(true);
    avatar.setEmotion(style.emotion);
    g_ui.speech_decorator_id = avatar.addDecorator(std::make_unique<agent_q::AgentQSpeechBubbleDecorator>(
        lv_screen_active(), message != nullptr && message[0] != '\0' ? message : "Agent-Q", style.background, style.foreground));
    if (should_lift_head_for_message(kind)) {
        trigger_agent_q_head_lift();
    }
    g_ui.speech_avatar = &avatar;
    g_ui.speech_mode = mode;
    g_ui.message_deadline = duration_ms > 0 ? xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms) : 0;
    return g_ui.speech_decorator_id >= 0;
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
}

void clear_agent_q_message_if_needed()
{
    if (g_ui.message_deadline == 0 || !tick_reached(g_ui.message_deadline)) {
        return;
    }
    clear_agent_q_avatar_ui();
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

void show_display_signal_decision(const char* message)
{
    if (show_avatar_decision(message)) {
        return;
    }
    ESP_LOGW(kTag, "display_signal could not show Agent-Q avatar decision UI");
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
        case PendingKind::none:
            break;
    }
}

void send_choice_response_if_needed()
{
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
                replace_active_session();
                write_connect_approved_response(g_pending.id);
                ESP_LOGI(kTag, "connect approved: id=%s", g_pending.id);
                show_result_and_clear_pending("Connected", AgentQMessageKind::success);
            } else {
                write_connect_rejected_response(g_pending.id, "rejected", "Connection rejected.");
                ESP_LOGI(kTag, "connect rejected: id=%s", g_pending.id);
                show_result_and_clear_pending("Connection rejected", AgentQMessageKind::rejected);
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
        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
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
        // disconnect is session-changing; reject it while an approval UI is
        // active so it cannot mutate session state mid-approval.
        if (g_pending.active) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!is_safe_session_id(session_id)) {
            write_error_response(id, "invalid_session", "Invalid sessionId.");
            return;
        }
        if (g_session.id[0] == '\0' || strcmp(session_id, g_session.id) != 0) {
            write_error_response(id, "invalid_session", "Session is unknown or already ended.");
            return;
        }
        clear_active_session();
        write_disconnect_result(id);
        ESP_LOGI(kTag, "disconnect: id=%s", id);
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
        clear_identification_if_needed();
        clear_agent_q_message_if_needed();
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
    g_session.clear();
    g_session.next_expiry_check = 0;
    g_pending.clear();
    g_identification.clear();
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

}  // namespace agent_q
