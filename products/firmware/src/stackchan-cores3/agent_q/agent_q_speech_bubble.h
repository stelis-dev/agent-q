#pragma once

#include <lvgl.h>
#include <stackchan/avatar/avatar/decorator.h>

namespace agent_q {

class AgentQSpeechBubbleDecorator : public stackchan::avatar::Decorator {
public:
    AgentQSpeechBubbleDecorator(lv_obj_t* parent, const char* text, lv_color_t background, lv_color_t foreground);
    ~AgentQSpeechBubbleDecorator() override;

private:
    lv_obj_t* container_ = nullptr;
    lv_obj_t* arrow_ = nullptr;
    lv_obj_t* bubble_ = nullptr;
    lv_obj_t* label_ = nullptr;
};

}  // namespace agent_q
