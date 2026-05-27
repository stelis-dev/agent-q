#include "agent_q_usb_request_mvp.h"

#include <string.h>

#include <ArduinoJson.h>
#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "hal/hal.h"
#include "lvgl.h"

namespace {

constexpr const char* kTag = "UsbRequestMvp";
constexpr size_t kLineBufferSize = 512;
constexpr size_t kResponseBufferSize = 384;
constexpr size_t kMaxRequestIdSize = 80;

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
char g_pending_id[kMaxRequestIdSize];
lv_obj_t* g_panel = nullptr;
bool g_usb_ready = false;
bool g_waiting_for_touch = false;

enum class PendingChoice {
    none,
    yes,
    no,
};

PendingChoice g_pending_choice = PendingChoice::none;

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

void write_json_response(const char* id, bool ok, const char* status, const char* error)
{
    JsonDocument response;
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["ok"] = ok;
    if (status != nullptr) {
        response["status"] = status;
    }
    if (error != nullptr) {
        response["error"] = error;
    }

    char buffer[kResponseBufferSize];
    size_t len = serializeJson(response, buffer, sizeof(buffer) - 2);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    usb_serial_jtag_write_bytes(buffer, len, pdMS_TO_TICKS(20));
    usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(50));
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
    lv_obj_set_size(button, 108, 44);
    lv_obj_align(button, LV_ALIGN_BOTTOM_MID, x, -14);
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
    {
        LvglLockGuard lock;
        clear_panel_locked();

        g_panel = lv_obj_create(lv_screen_active());
        lv_obj_set_size(g_panel, 286, 158);
        lv_obj_align(g_panel, LV_ALIGN_CENTER, 0, 18);
        lv_obj_remove_flag(g_panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_style_radius(g_panel, 12, 0);
        lv_obj_set_style_border_width(g_panel, 2, 0);
        lv_obj_set_style_bg_opa(g_panel, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(g_panel, lv_color_hex(0x123242), 0);
        lv_obj_set_style_border_color(g_panel, lv_color_hex(0x48B3FF), 0);

        lv_obj_t* title = lv_label_create(g_panel);
        lv_label_set_text(title, "Signal received");
        lv_obj_set_width(title, 244);
        lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(title, lv_color_hex(0xFFFFFF), 0);
        lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);

        lv_obj_t* subtitle = lv_label_create(g_panel);
        lv_label_set_text(subtitle, message != nullptr && message[0] != '\0' ? message : "USB request");
        lv_obj_set_width(subtitle, 244);
        lv_label_set_long_mode(subtitle, LV_LABEL_LONG_DOT);
        lv_obj_set_style_text_align(subtitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(subtitle, lv_color_hex(0xD7DEE6), 0);
        lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, 52);

        lv_obj_t* hint = lv_label_create(g_panel);
        lv_label_set_text(hint, "Choose YES or NO");
        lv_obj_set_width(hint, 244);
        lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(hint, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(hint, lv_color_hex(0x91D8FF), 0);
        lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 82);

        make_choice_button(g_panel, "NO", -62, lv_color_hex(0xA53B3B), on_no_clicked);
        make_choice_button(g_panel, "YES", 62, lv_color_hex(0x24875A), on_yes_clicked);

        lv_obj_move_foreground(g_panel);
    }
}

void clear_pending_request()
{
    {
        LvglLockGuard lock;
        clear_panel_locked();
    }
    g_pending_id[0] = '\0';
    g_waiting_for_touch = false;
    g_pending_choice = PendingChoice::none;
}

void send_choice_response_if_needed()
{
    if (!g_waiting_for_touch || g_pending_choice == PendingChoice::none) {
        return;
    }

    const bool approved = g_pending_choice == PendingChoice::yes;
    write_json_response(g_pending_id, approved, approved ? "approved" : "rejected", nullptr);
    ESP_LOGI(kTag, "display_signal %s: id=%s", approved ? "approved" : "rejected", g_pending_id);
    clear_pending_request();
}

void handle_line(const char* line)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, line);
    if (error) {
        write_json_response(nullptr, false, nullptr, "invalid_json");
        return;
    }

    const char* id = request["id"] | "";
    if (!is_safe_id(id)) {
        write_json_response(nullptr, false, nullptr, "invalid_id");
        return;
    }

    const char* method = request["method"] | "";
    if (strcmp(method, "display_signal") != 0) {
        write_json_response(id, false, nullptr, "unsupported_method");
        return;
    }

    if (g_waiting_for_touch) {
        write_json_response(id, false, nullptr, "busy");
        return;
    }

    const char* message = request["params"]["message"] | "USB request";
    strlcpy(g_pending_id, id, sizeof(g_pending_id));
    g_waiting_for_touch = true;
    g_pending_choice = PendingChoice::none;
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
            write_json_response(nullptr, false, nullptr, "line_too_long");
            continue;
        }

        g_line_buffer[g_line_size++] = c;
    }
}

}  // namespace

namespace agent_q {

void init_usb_request_mvp()
{
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
    ESP_LOGI(kTag, "USB request MVP ready");
}

void update_usb_request_mvp()
{
    send_choice_response_if_needed();
    if (!g_usb_ready) {
        return;
    }
    poll_usb_input();
}

}  // namespace agent_q
