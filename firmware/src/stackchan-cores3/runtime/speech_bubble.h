#pragma once

#include <lvgl.h>
#include <stackchan/avatar/avatar/decorator.h>

namespace signing {

class SpeechBubbleDecorator : public stackchan::avatar::Decorator {
public:
    SpeechBubbleDecorator(
        lv_obj_t* parent,
        const char* text,
        lv_color_t background,
        lv_color_t foreground,
        lv_event_cb_t click_callback = nullptr);
    ~SpeechBubbleDecorator() override;

private:
    lv_obj_t* container_ = nullptr;
    lv_obj_t* arrow_ = nullptr;
    lv_obj_t* bubble_ = nullptr;
    lv_obj_t* top_square_ = nullptr;
    lv_obj_t* left_square_ = nullptr;
    lv_obj_t* text_clip_ = nullptr;
    lv_obj_t* label_ = nullptr;
};

}  // namespace signing
