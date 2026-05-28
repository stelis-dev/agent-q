#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
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
constexpr size_t kGatewayDisplayBufferSize = 65;
constexpr int kModalWidth = 312;
constexpr int kApprovalModalHeight = 228;
constexpr int kIdentifyModalHeight = 168;
constexpr int kModalContentWidth = 286;
constexpr int kChoiceButtonWidth = 126;
constexpr int kChoiceButtonHeight = 54;

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
char g_pending_id[kMaxRequestIdSize];
char g_device_id[kDeviceIdSize];
char g_identification_code[kIdentifyCodeSize];
char g_session_id[kSessionIdSize];
char g_pending_gateway_name[kGatewayNameSize];
lv_obj_t* g_panel = nullptr;
bool g_usb_ready = false;
bool g_waiting_for_touch = false;
bool g_touch_armed = false;
bool g_showing_identification = false;
TickType_t g_pending_deadline = 0;
TickType_t g_identification_deadline = 0;
TickType_t g_session_expiry = 0;
TickType_t g_next_session_expiry_check = 0;
TaskHandle_t g_usb_task = nullptr;

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

PendingChoice g_pending_choice = PendingChoice::none;
PendingKind g_pending_kind = PendingKind::none;

bool tick_reached(TickType_t deadline)
{
    return static_cast<int32_t>(xTaskGetTickCount() - deadline) >= 0;
}

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
    if (g_waiting_for_touch) {
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
    response["sessionId"] = g_session_id;
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
    g_session_id[0] = '\0';
    g_session_expiry = 0;
}

void replace_active_session()
{
    format_session_id(g_session_id, sizeof(g_session_id));
    g_session_expiry = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionTtlMs);
}

void expire_session_if_needed()
{
    if (!tick_reached(g_next_session_expiry_check)) {
        return;
    }
    g_next_session_expiry_check = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionExpiryCheckMs);

    if (g_session_id[0] == '\0' || g_session_expiry == 0) {
        return;
    }
    if (tick_reached(g_session_expiry)) {
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
    if (g_waiting_for_touch) {
        g_pending_choice = PendingChoice::yes;
    }
}

void on_no_clicked(lv_event_t*)
{
    if (g_waiting_for_touch) {
        g_pending_choice = PendingChoice::no;
    }
}

void make_button_label(lv_obj_t* button, const char* text, lv_event_cb_t callback)
{
    lv_obj_t* label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
    lv_obj_center(label);
    lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(label, callback, LV_EVENT_CLICKED, nullptr);
}

void make_choice_button(lv_obj_t* parent, const char* text, int x, lv_color_t color, lv_event_cb_t callback)
{
    lv_obj_t* button = lv_button_create(parent);
    lv_obj_set_size(button, kChoiceButtonWidth, kChoiceButtonHeight);
    lv_obj_align(button, LV_ALIGN_BOTTOM_MID, x, -18);
    lv_obj_set_style_radius(button, 8, 0);
    lv_obj_set_style_bg_color(button, color, 0);
    lv_obj_set_style_bg_opa(button, LV_OPA_COVER, 0);
    lv_obj_set_style_text_color(button, lv_color_hex(0xFFFFFF), 0);
    lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, nullptr);
    make_button_label(button, text, callback);
}

void clear_panel_locked()
{
    if (g_panel != nullptr) {
        lv_obj_delete(g_panel);
        g_panel = nullptr;
    }
}

void show_pending_request_signal(const char* message)
{
    g_showing_identification = false;
    g_identification_deadline = 0;
    g_identification_code[0] = '\0';

    {
        LvglLockGuard lock;
        clear_panel_locked();

        g_panel = lv_obj_create(lv_screen_active());
        lv_obj_set_size(g_panel, kModalWidth, kApprovalModalHeight);
        lv_obj_align(g_panel, LV_ALIGN_CENTER, 0, 0);
        lv_obj_remove_flag(g_panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_style_radius(g_panel, 12, 0);
        lv_obj_set_style_border_width(g_panel, 2, 0);
        lv_obj_set_style_bg_opa(g_panel, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(g_panel, lv_color_hex(0x123242), 0);
        lv_obj_set_style_border_color(g_panel, lv_color_hex(0x48B3FF), 0);

        lv_obj_t* title = lv_label_create(g_panel);
        lv_label_set_text(title, "Signal received");
        lv_obj_set_width(title, kModalContentWidth);
        lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(title, lv_color_hex(0xFFFFFF), 0);
        lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 18);

        lv_obj_t* subtitle = lv_label_create(g_panel);
        lv_label_set_text(subtitle, message != nullptr && message[0] != '\0' ? message : "USB request");
        lv_obj_set_width(subtitle, kModalContentWidth);
        lv_label_set_long_mode(subtitle, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_text_align(subtitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_line_space(subtitle, 3, 0);
        lv_obj_set_style_text_color(subtitle, lv_color_hex(0xD7DEE6), 0);
        lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, 58);

        lv_obj_t* hint = lv_label_create(g_panel);
        lv_label_set_text(hint, "Choose YES or NO");
        lv_obj_set_width(hint, kModalContentWidth);
        lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(hint, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(hint, lv_color_hex(0x91D8FF), 0);
        lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 138);

        make_choice_button(g_panel, "NO", -66, lv_color_hex(0xA53B3B), on_no_clicked);
        make_choice_button(g_panel, "YES", 66, lv_color_hex(0x24875A), on_yes_clicked);

        lv_obj_move_foreground(g_panel);
    }
}

void show_identification_code(const char* code, uint32_t duration_ms)
{
    strlcpy(g_identification_code, code, sizeof(g_identification_code));
    g_showing_identification = true;
    g_identification_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms);

    {
        LvglLockGuard lock;
        clear_panel_locked();

        g_panel = lv_obj_create(lv_screen_active());
        lv_obj_set_size(g_panel, kModalWidth, kIdentifyModalHeight);
        lv_obj_align(g_panel, LV_ALIGN_CENTER, 0, 0);
        lv_obj_remove_flag(g_panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_style_radius(g_panel, 12, 0);
        lv_obj_set_style_border_width(g_panel, 2, 0);
        lv_obj_set_style_bg_opa(g_panel, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(g_panel, lv_color_hex(0x123242), 0);
        lv_obj_set_style_border_color(g_panel, lv_color_hex(0x48B3FF), 0);

        lv_obj_t* title = lv_label_create(g_panel);
        lv_label_set_text(title, "Identify device");
        lv_obj_set_width(title, kModalContentWidth);
        lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(title, lv_color_hex(0xFFFFFF), 0);
        lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

        lv_obj_t* code_label = lv_label_create(g_panel);
        lv_label_set_text(code_label, code);
        lv_obj_set_width(code_label, kModalContentWidth);
        lv_obj_set_style_text_align(code_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(code_label, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(code_label, lv_color_hex(0x91D8FF), 0);
        lv_obj_align(code_label, LV_ALIGN_TOP_MID, 0, 58);

        lv_obj_t* hint = lv_label_create(g_panel);
        lv_label_set_text(hint, "Confirm this code in Gateway");
        lv_obj_set_width(hint, kModalContentWidth);
        lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(hint, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(hint, lv_color_hex(0xD7DEE6), 0);
        lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 102);

        lv_obj_move_foreground(g_panel);
    }
}

void clear_identification_if_needed()
{
    if (!g_showing_identification || g_identification_deadline == 0 ||
        !tick_reached(g_identification_deadline)) {
        return;
    }

    {
        LvglLockGuard lock;
        clear_panel_locked();
    }
    g_showing_identification = false;
    g_identification_deadline = 0;
    g_identification_code[0] = '\0';
}

void clear_pending_request()
{
    {
        LvglLockGuard lock;
        clear_panel_locked();
    }
    g_pending_id[0] = '\0';
    g_waiting_for_touch = false;
    g_touch_armed = false;
    g_pending_choice = PendingChoice::none;
    g_pending_kind = PendingKind::none;
    g_pending_deadline = 0;
    g_pending_gateway_name[0] = '\0';
    g_showing_identification = false;
    g_identification_deadline = 0;
    g_identification_code[0] = '\0';
}

void show_connect_approval(const char* gateway_name)
{
    g_showing_identification = false;
    g_identification_deadline = 0;
    g_identification_code[0] = '\0';

    char display_label[kGatewayDisplayBufferSize];
    if (gateway_name == nullptr || gateway_name[0] == '\0') {
        strlcpy(display_label, "Agent-Q Gateway", sizeof(display_label));
    } else {
        strlcpy(display_label, gateway_name, sizeof(display_label));
    }

    {
        LvglLockGuard lock;
        clear_panel_locked();

        g_panel = lv_obj_create(lv_screen_active());
        lv_obj_set_size(g_panel, kModalWidth, kApprovalModalHeight);
        lv_obj_align(g_panel, LV_ALIGN_CENTER, 0, 0);
        lv_obj_remove_flag(g_panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_style_radius(g_panel, 12, 0);
        lv_obj_set_style_border_width(g_panel, 2, 0);
        lv_obj_set_style_bg_opa(g_panel, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(g_panel, lv_color_hex(0x123242), 0);
        lv_obj_set_style_border_color(g_panel, lv_color_hex(0xFFB347), 0);

        lv_obj_t* title = lv_label_create(g_panel);
        lv_label_set_text(title, "Connect Gateway");
        lv_obj_set_width(title, kModalContentWidth);
        lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(title, lv_color_hex(0xFFFFFF), 0);
        lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 18);

        lv_obj_t* subtitle = lv_label_create(g_panel);
        lv_label_set_text(subtitle, display_label);
        lv_obj_set_width(subtitle, kModalContentWidth);
        lv_label_set_long_mode(subtitle, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_text_align(subtitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_line_space(subtitle, 3, 0);
        lv_obj_set_style_text_color(subtitle, lv_color_hex(0xD7DEE6), 0);
        lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, 58);

        lv_obj_t* hint = lv_label_create(g_panel);
        lv_label_set_text(hint, "Allow connection?");
        lv_obj_set_width(hint, kModalContentWidth);
        lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(hint, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(hint, lv_color_hex(0xFFE2A8), 0);
        lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 138);

        make_choice_button(g_panel, "NO", -66, lv_color_hex(0xA53B3B), on_no_clicked);
        make_choice_button(g_panel, "YES", 66, lv_color_hex(0x24875A), on_yes_clicked);

        lv_obj_move_foreground(g_panel);
    }
}

void poll_touch_fallback()
{
    if (!g_waiting_for_touch || g_pending_choice != PendingChoice::none) {
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    if (touch.num == 0) {
        g_touch_armed = true;
        return;
    }
    if (!g_touch_armed) {
        return;
    }

    lv_area_t panel_area;
    {
        LvglLockGuard lock;
        if (g_panel == nullptr) {
            return;
        }
        lv_obj_get_coords(g_panel, &panel_area);
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

    // Use the lower half as a hardware-specific fallback hit area. The visible
    // LVGL buttons still receive normal click events when the input driver does
    // deliver them.
    if (relative_y < panel_height / 2) {
        return;
    }

    g_pending_choice = relative_x < panel_width / 2 ? PendingChoice::no : PendingChoice::yes;
    g_touch_armed = false;
}

void send_choice_response_if_needed()
{
    poll_touch_fallback();

    if (!g_waiting_for_touch || g_pending_choice == PendingChoice::none) {
        if (g_waiting_for_touch && g_pending_deadline != 0 &&
            tick_reached(g_pending_deadline)) {
            // Device leaves awaiting_approval before reporting the result.
            g_waiting_for_touch = false;
            switch (g_pending_kind) {
                case PendingKind::display_signal:
                    write_display_signal_result(g_pending_id, "rejected", "timeout", "Request timed out.");
                    ESP_LOGI(kTag, "display_signal timed out: id=%s", g_pending_id);
                    break;
                case PendingKind::connect:
                    write_connect_rejected_response(g_pending_id, "timeout", "Connection approval timed out.");
                    ESP_LOGI(kTag, "connect timed out: id=%s", g_pending_id);
                    break;
                case PendingKind::none:
                    break;
            }
            clear_pending_request();
        }
        return;
    }

    const bool approved = g_pending_choice == PendingChoice::yes;
    g_waiting_for_touch = false;
    switch (g_pending_kind) {
        case PendingKind::display_signal:
            write_display_signal_result(g_pending_id, approved ? "approved" : "rejected", nullptr, nullptr);
            ESP_LOGI(kTag, "display_signal %s: id=%s", approved ? "approved" : "rejected", g_pending_id);
            break;
        case PendingKind::connect:
            if (approved) {
                replace_active_session();
                write_connect_approved_response(g_pending_id);
                ESP_LOGI(kTag, "connect approved: id=%s", g_pending_id);
            } else {
                write_connect_rejected_response(g_pending_id, "rejected", "Connection rejected.");
                ESP_LOGI(kTag, "connect rejected: id=%s", g_pending_id);
            }
            break;
        case PendingKind::none:
            break;
    }
    clear_pending_request();
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
        if (g_waiting_for_touch) {
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
        if (g_waiting_for_touch) {
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

        strlcpy(g_pending_id, id, sizeof(g_pending_id));
        strlcpy(g_pending_gateway_name, gateway_name, sizeof(g_pending_gateway_name));
        g_waiting_for_touch = true;
        g_touch_armed = false;
        g_pending_choice = PendingChoice::none;
        g_pending_kind = PendingKind::connect;
        g_pending_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(approval_timeout_ms);
        show_connect_approval(g_pending_gateway_name);
        ESP_LOGI(kTag, "connect waiting for YES/NO: id=%s gateway=%s", id, g_pending_gateway_name);
        return;
    }

    if (strcmp(type, "disconnect") == 0) {
        // disconnect is session-changing; reject it while an approval modal is
        // open so it cannot mutate session state mid-approval.
        if (g_waiting_for_touch) {
            write_error_response(id, "busy", "Device is awaiting physical input.");
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!is_safe_session_id(session_id)) {
            write_error_response(id, "invalid_session", "Invalid sessionId.");
            return;
        }
        if (g_session_id[0] == '\0' || strcmp(session_id, g_session_id) != 0) {
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

    if (g_waiting_for_touch) {
        write_error_response(id, "busy", "Device is awaiting physical input.");
        return;
    }

    const char* message = request["params"]["message"] | "USB request";
    strlcpy(g_pending_id, id, sizeof(g_pending_id));
    g_waiting_for_touch = true;
    g_touch_armed = false;
    g_pending_choice = PendingChoice::none;
    g_pending_kind = PendingKind::display_signal;
    g_pending_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kDisplaySignalTimeoutMs);
    show_pending_request_signal(message);
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
        expire_session_if_needed();
        send_choice_response_if_needed();
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
    g_session_id[0] = '\0';
    g_session_expiry = 0;
    g_pending_gateway_name[0] = '\0';
    g_pending_kind = PendingKind::none;

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
