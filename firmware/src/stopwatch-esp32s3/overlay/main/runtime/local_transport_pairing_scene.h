#pragma once

#include <freertos/FreeRTOS.h>
#include <lvgl.h>

namespace stopwatch_target {

class LocalTransportPairingScene {
public:
    void create(lv_obj_t* parent);
    void destroy();
    bool show_pairing(const char* payload, TickType_t deadline);
    void show_result(const char* message, bool error);
    void set_visible(bool visible);
    void update(TickType_t now);

private:
    lv_obj_t* scene_root_ = nullptr;
    lv_obj_t* title_label_ = nullptr;
    lv_obj_t* qr_code_ = nullptr;
    lv_obj_t* detail_label_ = nullptr;
    TickType_t deadline_ = 0;
    uint32_t rendered_seconds_ = UINT32_MAX;
    bool visible_ = false;
};

}  // namespace stopwatch_target
