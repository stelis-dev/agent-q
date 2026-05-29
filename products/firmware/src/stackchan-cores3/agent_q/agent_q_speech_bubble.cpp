#include "agent_q_speech_bubble.h"

#include <algorithm>
#include <string.h>

LV_IMAGE_DECLARE(default_bubble_arrow);

namespace agent_q {

namespace {

constexpr int kContainerX = 0;
constexpr int kContainerY = 83;
constexpr int kContainerWidth = 300;
constexpr int kContainerHeight = 74;
constexpr int kArrowX = 40;
constexpr int kArrowY = -15;
constexpr int kTextMarginX = 20;
constexpr int kBubbleMinWidth = 90;
constexpr int kBubbleMaxWidth = 280;
constexpr int kBubbleHeight = 52;
constexpr int kBubbleMinOffsetX = 66;
constexpr int kBubbleMaxOffsetX = 0;

int map_width_to_offset(int width)
{
    const int from_span = kBubbleMaxWidth - kBubbleMinWidth;
    if (from_span <= 0) {
        return kBubbleMaxOffsetX;
    }
    const int to_span = kBubbleMaxOffsetX - kBubbleMinOffsetX;
    return kBubbleMinOffsetX + ((width - kBubbleMinWidth) * to_span / from_span);
}

void make_clickable(lv_obj_t* object, lv_event_cb_t callback)
{
    if (object == nullptr || callback == nullptr) {
        return;
    }

    lv_obj_add_flag(object, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(object, callback, LV_EVENT_CLICKED, nullptr);
}

}  // namespace

AgentQSpeechBubbleDecorator::AgentQSpeechBubbleDecorator(
    lv_obj_t* parent,
    const char* text,
    lv_color_t background,
    lv_color_t foreground,
    lv_event_cb_t click_callback)
{
    const char* display_text = text != nullptr && text[0] != '\0' ? text : "Agent-Q";

    if (parent != nullptr) {
        lv_obj_remove_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_scrollbar_mode(parent, LV_SCROLLBAR_MODE_OFF);
    }

    container_ = lv_obj_create(parent);
    lv_obj_set_size(container_, kContainerWidth, kContainerHeight);
    lv_obj_align(container_, LV_ALIGN_CENTER, kContainerX, kContainerY);
    lv_obj_remove_flag(container_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(container_, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(container_, 0, 0);
    lv_obj_set_style_border_width(container_, 0, 0);
    lv_obj_set_style_bg_opa(container_, LV_OPA_TRANSP, 0);
    lv_obj_set_style_pad_all(container_, 0, 0);
    make_clickable(container_, click_callback);

    arrow_ = lv_image_create(container_);
    lv_image_set_src(arrow_, &default_bubble_arrow);
    lv_obj_align(arrow_, LV_ALIGN_CENTER, kArrowX, kArrowY);
    lv_obj_set_style_image_recolor_opa(arrow_, LV_OPA_COVER, 0);
    lv_obj_set_style_image_recolor(arrow_, background, 0);
    make_clickable(arrow_, click_callback);

    bubble_ = lv_obj_create(container_);
    lv_obj_set_size(bubble_, kBubbleMaxWidth, kBubbleHeight);
    lv_obj_align(bubble_, LV_ALIGN_CENTER, 0, 11);
    lv_obj_remove_flag(bubble_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(bubble_, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(bubble_, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_border_width(bubble_, 0, 0);
    lv_obj_set_style_bg_color(bubble_, background, 0);
    lv_obj_set_style_bg_opa(bubble_, LV_OPA_COVER, 0);
    make_clickable(bubble_, click_callback);

    label_ = lv_label_create(bubble_);
    lv_label_set_text(label_, display_text);
    lv_label_set_long_mode(label_, LV_LABEL_LONG_MODE_DOTS);
    lv_obj_set_width(label_, kBubbleMaxWidth - kTextMarginX * 2);
    lv_obj_set_style_text_align(label_, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(label_, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label_, foreground, 0);
    lv_obj_align(label_, LV_ALIGN_CENTER, 0, 0);
    make_clickable(label_, click_callback);

    lv_point_t text_size;
    lv_text_get_size(&text_size,
                     display_text,
                     lv_obj_get_style_text_font(label_, LV_PART_MAIN),
                     0,
                     0,
                     LV_COORD_MAX,
                     LV_TEXT_FLAG_NONE);
    const int measured_width = static_cast<int>(text_size.x) + kTextMarginX * 2;
    int bubble_width = std::min(measured_width, kBubbleMaxWidth);
    bubble_width = std::max(bubble_width, kBubbleMinWidth);
    lv_obj_set_width(bubble_, bubble_width);
    lv_obj_set_x(bubble_, map_width_to_offset(bubble_width));
}

AgentQSpeechBubbleDecorator::~AgentQSpeechBubbleDecorator()
{
    if (container_ != nullptr) {
        lv_obj_delete(container_);
        container_ = nullptr;
        arrow_ = nullptr;
        bubble_ = nullptr;
        label_ = nullptr;
    }
}

}  // namespace agent_q
