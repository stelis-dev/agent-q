#include "clock_scene.h"

#include "assets/watch/watch_assets_generated.h"
#include "display_geometry.h"

#include <math.h>
#include <stdint.h>

namespace stopwatch_target {
namespace {

constexpr lv_value_precise_t kClockPivotCoordinate = kDisplayCenterPx;
constexpr float kClockPivot = static_cast<float>(kClockPivotCoordinate);
constexpr float kPi = 3.14159265358979323846F;

extern const uint8_t watch_face_i8_start[] asm("_binary_clock_1_face_i8_bin_start");
extern const uint8_t watch_face_i8_end[] asm("_binary_clock_1_face_i8_bin_end");

lv_image_dsc_t kWatchFaceImage = {};

void init_watch_face_image()
{
    kWatchFaceImage = {
        .header = {
            .magic = LV_IMAGE_HEADER_MAGIC,
            .cf = LV_COLOR_FORMAT_I8,
            .flags = 0,
            .w = static_cast<uint32_t>(kWatchFaceImageWidth),
            .h = static_cast<uint32_t>(kWatchFaceImageHeight),
            .stride = static_cast<uint32_t>(kWatchFaceImageStride),
            .reserved_2 = 0,
        },
        .data_size = static_cast<uint32_t>(watch_face_i8_end - watch_face_i8_start),
        .data = watch_face_i8_start,
        .reserved = nullptr,
        .reserved_2 = nullptr,
    };
}

lv_obj_t* make_line(lv_obj_t* parent, lv_point_precise_t* points, uint32_t width, lv_color_t color, lv_opa_t opacity)
{
    lv_obj_t* line = lv_line_create(parent);
    lv_obj_set_size(line, kDisplaySizePx, kDisplaySizePx);
    lv_obj_set_pos(line, 0, 0);
    lv_line_set_points_mutable(line, points, 2);
    lv_obj_set_style_line_width(line, width, LV_PART_MAIN);
    lv_obj_set_style_line_color(line, color, LV_PART_MAIN);
    lv_obj_set_style_line_opa(line, opacity, LV_PART_MAIN);
    lv_obj_set_style_line_rounded(line, false, LV_PART_MAIN);
    lv_obj_clear_flag(line, LV_OBJ_FLAG_SCROLLABLE);
    return line;
}

lv_value_precise_t clock_coordinate(float value)
{
    return static_cast<lv_value_precise_t>(lroundf(value));
}

float normalize_degrees(float degrees)
{
    float normalized = fmodf(degrees, 360.0F);
    if (normalized < 0.0F) {
        normalized += 360.0F;
    }
    if (normalized < 0.0001F || 360.0F - normalized < 0.0001F) {
        return 0.0F;
    }
    return normalized;
}

void set_twelve_o_clock_hand_points(
    lv_point_precise_t* points,
    int tail_length,
    int hand_length)
{
    points[0] = {
        .x = kClockPivotCoordinate,
        .y = clock_coordinate(kClockPivot + static_cast<float>(tail_length)),
    };
    points[1] = {
        .x = kClockPivotCoordinate,
        .y = clock_coordinate(kClockPivot - static_cast<float>(hand_length)),
    };
}

void set_hand_points(
    lv_point_precise_t* points,
    float degrees,
    int tail_length,
    int hand_length)
{
    const float normalized_degrees = normalize_degrees(degrees);
    if (normalized_degrees == 0.0F) {
        set_twelve_o_clock_hand_points(points, tail_length, hand_length);
        return;
    }
    const float radians = normalized_degrees * kPi / 180.0F;
    const float sin_value = sinf(radians);
    const float cos_value = cosf(radians);
    points[0] = {
        .x = clock_coordinate(kClockPivot - sin_value * static_cast<float>(tail_length)),
        .y = clock_coordinate(kClockPivot + cos_value * static_cast<float>(tail_length)),
    };
    points[1] = {
        .x = clock_coordinate(kClockPivot + sin_value * static_cast<float>(hand_length)),
        .y = clock_coordinate(kClockPivot - cos_value * static_cast<float>(hand_length)),
    };
}

}  // namespace

void ClockScene::create(lv_obj_t* parent)
{
    destroy();
    parent_ = parent;
    if (parent_ == nullptr) {
        return;
    }

    scene_root_ = lv_obj_create(parent_);
    lv_obj_set_size(scene_root_, kDisplaySizePx, kDisplaySizePx);
    lv_obj_align(scene_root_, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(scene_root_, lv_color_hex(0x050607), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(scene_root_, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_border_width(scene_root_, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(scene_root_, kDisplayCenterPx, LV_PART_MAIN);
    lv_obj_set_style_pad_all(scene_root_, 0, LV_PART_MAIN);
    lv_obj_clear_flag(scene_root_, LV_OBJ_FLAG_SCROLLABLE);

    init_watch_face_image();
    face_image_ = lv_image_create(scene_root_);
    lv_image_set_src(face_image_, &kWatchFaceImage);
    lv_obj_align(face_image_, LV_ALIGN_CENTER, 0, 0);
    lv_obj_clear_flag(face_image_, LV_OBJ_FLAG_SCROLLABLE);

    const TimeHms time = GetHAL().getTimeHms();
    update_hand_points(time);
    hour_hand_ = make_line(scene_root_, hour_points_, 8, lv_color_hex(0xF4E8D0), LV_OPA_COVER);
    minute_hand_ = make_line(scene_root_, minute_points_, 6, lv_color_hex(0xF4E8D0), LV_OPA_COVER);
    second_hand_ = make_line(scene_root_, second_points_, 3, lv_color_hex(0xB74D45), LV_OPA_COVER);

    center_dot_ = lv_obj_create(scene_root_);
    lv_obj_set_size(center_dot_, 16, 16);
    lv_obj_set_style_radius(center_dot_, 8, LV_PART_MAIN);
    lv_obj_set_style_border_width(center_dot_, 0, LV_PART_MAIN);
    lv_obj_set_style_bg_color(center_dot_, lv_color_hex(0xB74D45), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(center_dot_, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_align(center_dot_, LV_ALIGN_CENTER, 0, 0);
    lv_obj_clear_flag(center_dot_, LV_OBJ_FLAG_SCROLLABLE);

    set_visible(false);
}

void ClockScene::destroy()
{
    if (scene_root_ != nullptr) {
        lv_obj_delete(scene_root_);
    }
    scene_root_ = nullptr;
    face_image_ = nullptr;
    hour_hand_ = nullptr;
    minute_hand_ = nullptr;
    second_hand_ = nullptr;
    center_dot_ = nullptr;
    parent_ = nullptr;
    rendered_second_ = -1;
    visible_ = false;
}

void ClockScene::set_visible(bool visible)
{
    const bool became_visible = visible && !visible_;
    visible_ = visible;
    if (scene_root_ == nullptr) {
        return;
    }
    if (visible) {
        if (became_visible) {
            rendered_second_ = -1;
        }
        lv_obj_remove_flag(scene_root_, LV_OBJ_FLAG_HIDDEN);
        lv_obj_move_foreground(scene_root_);
    } else {
        lv_obj_add_flag(scene_root_, LV_OBJ_FLAG_HIDDEN);
    }
}

void ClockScene::update(uint32_t /*now_ms*/)
{
    if (!visible_) {
        return;
    }
    const TimeHms time = GetHAL().getTimeHms();
    if (!time.isValid() || rendered_second_ == static_cast<int>(time.second)) {
        return;
    }
    invalidate_hands();
    update_hand_points(time);
    refresh_hand_lines();
    rendered_second_ = static_cast<int>(time.second);
    invalidate_hands();
}

void ClockScene::update_hand_points(const TimeHms& time)
{
    const float second_degrees = static_cast<float>(time.second) * 6.0F;
    const float minute_degrees = (static_cast<float>(time.minute) + static_cast<float>(time.second) / 60.0F) * 6.0F;
    const float hour_degrees =
        (static_cast<float>(time.hour % 12) + static_cast<float>(time.minute) / 60.0F) * 30.0F;

    set_hand_points(hour_points_, hour_degrees, 16, 82);
    set_hand_points(minute_points_, minute_degrees, 18, 122);
    set_hand_points(second_points_, second_degrees, 24, 142);
}

void ClockScene::refresh_hand_lines()
{
    if (hour_hand_ != nullptr) {
        lv_line_set_points_mutable(hour_hand_, hour_points_, 2);
    }
    if (minute_hand_ != nullptr) {
        lv_line_set_points_mutable(minute_hand_, minute_points_, 2);
    }
    if (second_hand_ != nullptr) {
        lv_line_set_points_mutable(second_hand_, second_points_, 2);
    }
}

void ClockScene::invalidate_hands()
{
    lv_obj_t* hands[] = {hour_hand_, minute_hand_, second_hand_, center_dot_};
    for (lv_obj_t* hand : hands) {
        if (hand != nullptr) {
            lv_obj_invalidate(hand);
        }
    }
}

}  // namespace stopwatch_target
