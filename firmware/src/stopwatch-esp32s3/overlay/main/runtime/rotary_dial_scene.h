#pragma once

#include <lvgl.h>

namespace stopwatch_target {

class RotaryDialScene {
public:
    void create(lv_obj_t* parent);
    void destroy();
    void reset();
    void set_visible(bool visible);

    int digit_at_point(int x, int y) const;
    bool digit_reached_stop(char digit) const;
    void advance_clockwise_from_touch(int previous_x, int previous_y, int x, int y, char digit);
    void set_rotation_degrees(float degrees, bool force_render = false);
    float rotation_degrees() const { return rotation_degrees_; }

private:
    lv_obj_t* parent_ = nullptr;
    lv_obj_t* base_image_ = nullptr;
    lv_obj_t* dial_image_ = nullptr;
    uint8_t* dial_frame_index_buffer_ = nullptr;
    uint8_t* dial_frame_rgb565_buffer_ = nullptr;
    void* dial_frame_decompressor_ = nullptr;
    lv_image_dsc_t dial_frame_dsc_ = {};
    float rotation_degrees_ = 0.0F;
    float rendered_rotation_degrees_ = 0.0F;
    int rendered_frame_index_ = -1;
    bool dial_frame_ready_ = false;
};

}  // namespace stopwatch_target
