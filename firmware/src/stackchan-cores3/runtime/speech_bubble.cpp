#include "speech_bubble.h"

#include <algorithm>
#include <string.h>

LV_IMAGE_DECLARE(default_bubble_arrow);

namespace signing {

namespace {

constexpr int kContainerX = 0;
constexpr int kContainerY = 0;
constexpr int kContainerWidth = 300;
constexpr int kArrowWidth = 28;
constexpr int kArrowMinX = 6;
constexpr int kArrowMaxX = 72;
constexpr int kArrowBubbleOverlap = 19;
constexpr int kArrowBottomMargin = 13;
constexpr int kTextBaseInsetX = 2;
constexpr int kTextOpticalShiftX = 1;
constexpr int kTextInsetY = 4;
constexpr int kTextWidthSafety = 6;
constexpr int kBubbleMinWidth = 64;
constexpr int kBubbleMaxWidth = 280;
constexpr int kBubbleMinHeight = 40;
constexpr int kBubbleMaxHeight = 96;
constexpr int kBubbleCornerRadius = 10;
constexpr int kBubbleTopSquareHeight = kBubbleCornerRadius;
constexpr int kBubbleLeftSquareWidth = kBubbleCornerRadius;

void make_clickable(lv_obj_t* object, lv_event_cb_t callback)
{
    if (object == nullptr || callback == nullptr) {
        return;
    }

    lv_obj_add_flag(object, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(object, callback, LV_EVENT_CLICKED, nullptr);
}

constexpr int text_left_inset()
{
    return kTextBaseInsetX + kTextOpticalShiftX;
}

constexpr int text_right_inset()
{
    return kTextBaseInsetX - kTextOpticalShiftX;
}

int text_width_for_bubble(int bubble_width)
{
    return bubble_width - text_left_inset() - text_right_inset();
}

int bubble_width_for_text(const lv_point_t& text_size)
{
    const int measured_width =
        static_cast<int>(text_size.x) + text_left_inset() + text_right_inset() +
        kTextWidthSafety;
    return std::max(std::min(measured_width, kBubbleMaxWidth), kBubbleMinWidth);
}

int bubble_height_for_wrapped_text(const lv_point_t& text_size)
{
    const int measured_height = static_cast<int>(text_size.y) + 2 * kTextInsetY;
    return std::max(std::min(measured_height, kBubbleMaxHeight), kBubbleMinHeight);
}

int arrow_y_for_bubble_height(int bubble_height)
{
    return std::max(0, bubble_height - kArrowBubbleOverlap);
}

int container_height_for_bubble_height(int bubble_height)
{
    return arrow_y_for_bubble_height(bubble_height) + kArrowWidth + kArrowBottomMargin;
}

int arrow_x_for_bubble(int bubble_width)
{
    return std::min(std::max((bubble_width - kArrowWidth) / 3, kArrowMinX), kArrowMaxX);
}

}  // namespace

SpeechBubbleDecorator::SpeechBubbleDecorator(
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

    lv_point_t unwrapped_text_size;
    lv_text_get_size(&unwrapped_text_size,
                     display_text,
                     &lv_font_montserrat_14,
                     0,
                     0,
                     LV_COORD_MAX,
                     LV_TEXT_FLAG_NONE);
    const int bubble_width = bubble_width_for_text(unwrapped_text_size);
    const int text_width = text_width_for_bubble(bubble_width);
    lv_point_t wrapped_text_size;
    lv_text_get_size(&wrapped_text_size,
                     display_text,
                     &lv_font_montserrat_14,
                     0,
                     0,
                     text_width,
                     LV_TEXT_FLAG_NONE);
    const int bubble_height = bubble_height_for_wrapped_text(wrapped_text_size);
    const int container_height = container_height_for_bubble_height(bubble_height);
    const int arrow_y = arrow_y_for_bubble_height(bubble_height);

    container_ = lv_obj_create(parent);
    lv_obj_set_size(container_, kContainerWidth, container_height);
    lv_obj_align(container_, LV_ALIGN_TOP_LEFT, kContainerX, kContainerY);
    lv_obj_add_flag(container_, LV_OBJ_FLAG_FLOATING);
    lv_obj_remove_flag(container_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(container_, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(container_, 0, 0);
    lv_obj_set_style_border_width(container_, 0, 0);
    lv_obj_set_style_bg_opa(container_, LV_OPA_TRANSP, 0);
    lv_obj_set_style_pad_all(container_, 0, 0);
    make_clickable(container_, click_callback);

    arrow_ = lv_image_create(container_);
    lv_image_set_src(arrow_, &default_bubble_arrow);
    lv_image_set_rotation(arrow_, 1800);
    lv_obj_align(arrow_, LV_ALIGN_TOP_LEFT, kArrowMinX, arrow_y);
    lv_obj_set_style_image_recolor_opa(arrow_, LV_OPA_COVER, 0);
    lv_obj_set_style_image_recolor(arrow_, background, 0);
    make_clickable(arrow_, click_callback);

    bubble_ = lv_obj_create(container_);
    lv_obj_set_size(bubble_, bubble_width, bubble_height);
    lv_obj_align(bubble_, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_obj_remove_flag(bubble_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(bubble_, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(bubble_, kBubbleCornerRadius, 0);
    lv_obj_set_style_border_width(bubble_, 0, 0);
    lv_obj_set_style_bg_color(bubble_, background, 0);
    lv_obj_set_style_bg_opa(bubble_, LV_OPA_COVER, 0);
    make_clickable(bubble_, click_callback);

    top_square_ = lv_obj_create(container_);
    lv_obj_remove_style_all(top_square_);
    lv_obj_set_size(top_square_, bubble_width, kBubbleTopSquareHeight);
    lv_obj_align(top_square_, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_obj_set_style_bg_color(top_square_, background, 0);
    lv_obj_set_style_bg_opa(top_square_, LV_OPA_COVER, 0);
    make_clickable(top_square_, click_callback);

    left_square_ = lv_obj_create(container_);
    lv_obj_remove_style_all(left_square_);
    lv_obj_set_size(left_square_, kBubbleLeftSquareWidth, bubble_height);
    lv_obj_align(left_square_, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_obj_set_style_bg_color(left_square_, background, 0);
    lv_obj_set_style_bg_opa(left_square_, LV_OPA_COVER, 0);
    make_clickable(left_square_, click_callback);

    text_clip_ = lv_obj_create(container_);
    lv_obj_remove_style_all(text_clip_);
    lv_obj_set_size(text_clip_, bubble_width, bubble_height);
    lv_obj_align(text_clip_, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_obj_remove_flag(text_clip_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(text_clip_, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_pad_all(text_clip_, 0, 0);
    make_clickable(text_clip_, click_callback);

    label_ = lv_label_create(text_clip_);
    lv_obj_remove_style_all(label_);
    lv_label_set_text(label_, display_text);
    lv_label_set_long_mode(label_, LV_LABEL_LONG_MODE_WRAP);
    lv_obj_set_width(label_, text_width);
    lv_obj_set_style_text_align(label_, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(label_, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label_, foreground, 0);
    lv_obj_set_style_text_opa(label_, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(label_, 0, 0);
    lv_obj_align(label_, LV_ALIGN_CENTER, 0, 0);
    make_clickable(label_, click_callback);

    lv_obj_align(label_, LV_ALIGN_LEFT_MID, text_left_inset(), 0);
    lv_obj_align(arrow_, LV_ALIGN_TOP_LEFT, arrow_x_for_bubble(bubble_width), arrow_y);
}

SpeechBubbleDecorator::~SpeechBubbleDecorator()
{
    if (container_ != nullptr) {
        lv_obj_delete(container_);
        container_ = nullptr;
        arrow_ = nullptr;
        bubble_ = nullptr;
        top_square_ = nullptr;
        left_square_ = nullptr;
        text_clip_ = nullptr;
        label_ = nullptr;
    }
}

}  // namespace signing
