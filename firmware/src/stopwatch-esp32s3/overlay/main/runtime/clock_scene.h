#pragma once

#include <hal/hal.h>
#include <lvgl.h>
#include <stdint.h>

namespace stopwatch_target {

class ClockScene {
public:
    void create(lv_obj_t* parent);
    void destroy();
    void set_visible(bool visible);
    void update(uint32_t now_ms);

private:
    lv_obj_t* parent_ = nullptr;
    lv_obj_t* scene_root_ = nullptr;
    lv_obj_t* face_image_ = nullptr;
    lv_obj_t* hour_hand_ = nullptr;
    lv_obj_t* minute_hand_ = nullptr;
    lv_obj_t* second_hand_ = nullptr;
    lv_obj_t* center_dot_ = nullptr;
    lv_point_precise_t hour_points_[2] = {};
    lv_point_precise_t minute_points_[2] = {};
    lv_point_precise_t second_points_[2] = {};
    int rendered_second_ = -1;
    bool visible_ = false;

    void update_hand_points(const TimeHms& time);
    void refresh_hand_lines();
    void invalidate_hands();
};

}  // namespace stopwatch_target
