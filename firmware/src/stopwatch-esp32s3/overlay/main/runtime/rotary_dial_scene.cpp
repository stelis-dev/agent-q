#include "rotary_dial_scene.h"

#include "assets/dial/dial_assets_generated.h"

#include <esp_heap_caps.h>
#include <lgfx/utility/lgfx_miniz.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>

namespace stopwatch_target {
namespace {

constexpr int kScreenCenter = 233;
constexpr int kDigitRadius = 27;
constexpr int kDigitHitRadius = 44;
constexpr int kDialStopContactX = 328;
constexpr int kDialStopContactY = 321;
constexpr float kDialRenderStepDegrees = static_cast<float>(kDialFrameStepDegrees);
constexpr float kDialStopCommitToleranceDegrees = 4.0F;
constexpr float kPi = 3.14159265358979323846F;

extern const uint8_t dial_baseplate_rgb565a8_start[] asm("_binary_1_baseplate_rgb565a8_bin_start");
extern const uint8_t dial_baseplate_rgb565a8_end[] asm("_binary_1_baseplate_rgb565a8_bin_end");
extern const uint8_t dial_frame_idx8_deflate_start[] asm("_binary_2_dial_frames_idx8_deflate_bin_start");
extern const uint8_t dial_frame_idx8_deflate_end[] asm("_binary_2_dial_frames_idx8_deflate_bin_end");

lv_image_dsc_t kDialBaseplateImage = {};

struct DigitPosition {
    char digit;
    int x;
    int y;
};

constexpr DigitPosition kDigitPositions[10] = {
    {'1', 363, 221},
    {'2', 340, 158},
    {'3', 288, 114},
    {'4', 221, 103},
    {'5', 158, 126},
    {'6', 114, 177},
    {'7', 103, 245},
    {'8', 126, 308},
    {'9', 177, 351},
    {'0', 244, 363},
};

float normalize_angle_delta(float degrees)
{
    while (degrees > 180.0F) {
        degrees -= 360.0F;
    }
    while (degrees < -180.0F) {
        degrees += 360.0F;
    }
    return degrees;
}

float clockwise_angle_delta(float from_degrees, float to_degrees)
{
    float delta = normalize_angle_delta(to_degrees - from_degrees);
    if (delta < 0.0F) {
        delta += 360.0F;
    }
    return delta;
}

float point_angle_degrees(int x, int y)
{
    return atan2f(
               static_cast<float>(y - kScreenCenter),
               static_cast<float>(x - kScreenCenter)) *
           180.0F / kPi;
}

float stop_rotation_for_digit(char digit)
{
    const float stop_angle = point_angle_degrees(kDialStopContactX, kDialStopContactY);
    for (size_t index = 0; index < 10; ++index) {
        if (kDigitPositions[index].digit != digit) {
            continue;
        }
        const float digit_angle = point_angle_degrees(kDigitPositions[index].x, kDigitPositions[index].y);
        const float rotation = clockwise_angle_delta(digit_angle, stop_angle);
        const float max_rotation = static_cast<float>(kDialFrameMaxDegrees);
        return rotation > max_rotation ? max_rotation : rotation;
    }
    return 0.0F;
}

void init_image_descriptor(
    lv_image_dsc_t* image,
    const uint8_t* start,
    const uint8_t* end,
    int width,
    int height,
    int stride,
    lv_color_format_t format = LV_COLOR_FORMAT_RGB565A8)
{
    *image = {
        .header = {
            .magic = LV_IMAGE_HEADER_MAGIC,
            .cf = format,
            .flags = 0,
            .w = static_cast<uint32_t>(width),
            .h = static_cast<uint32_t>(height),
            .stride = static_cast<uint32_t>(stride),
            .reserved_2 = 0,
        },
        .data_size = static_cast<uint32_t>(end - start),
        .data = start,
        .reserved = nullptr,
        .reserved_2 = nullptr,
    };
}

int frame_index_for_degrees(float degrees)
{
    if (degrees <= 0.0F) {
        return 0;
    }
    if (degrees >= static_cast<float>(kDialFrameMaxDegrees)) {
        return kDialFrameCount - 1;
    }
    int index = static_cast<int>(roundf(degrees / static_cast<float>(kDialFrameStepDegrees)));
    if (index < 0) {
        index = 0;
    }
    if (index >= kDialFrameCount) {
        index = kDialFrameCount - 1;
    }
    return index;
}

bool render_indexed_frame(
    uint8_t* index_buffer,
    uint8_t* rgb565_buffer,
    lgfx_tinfl_decompressor* decompressor,
    int frame_index)
{
    if (index_buffer == nullptr || rgb565_buffer == nullptr || decompressor == nullptr ||
        frame_index < 0 || frame_index >= kDialFrameCount) {
        return false;
    }
    const uint32_t frame_offset = kDialFrameOffsets[frame_index];
    const uint32_t compressed_size = kDialFrameCompressedSizes[frame_index];
    const uint8_t* compressed_start = dial_frame_idx8_deflate_start + frame_offset;
    const uint8_t* compressed_end = compressed_start + compressed_size;
    if (compressed_end > dial_frame_idx8_deflate_end) {
        return false;
    }

    const size_t pixel_count = static_cast<size_t>(kDialFrameImageWidth) *
                               static_cast<size_t>(kDialFrameImageHeight);
    size_t input_size = compressed_size;
    size_t decompressed_size = pixel_count;
    lgfx_tinfl_init(decompressor);
    const lgfx_tinfl_status status = lgfx_tinfl_decompress(
        decompressor,
        compressed_start,
        &input_size,
        index_buffer,
        index_buffer,
        &decompressed_size,
        TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (status != TINFL_STATUS_DONE || decompressed_size != pixel_count) {
        return false;
    }

    uint16_t* output = reinterpret_cast<uint16_t*>(rgb565_buffer);
    for (size_t index = 0; index < pixel_count; ++index) {
        output[index] = kDialFramePalette[index_buffer[index]];
    }
    return true;
}

lv_obj_t* make_centered_dial_image(lv_obj_t* parent, const lv_image_dsc_t* image)
{
    lv_obj_t* object = lv_image_create(parent);
    lv_image_set_src(object, image);
    lv_obj_align(object, LV_ALIGN_CENTER, 0, 0);
    lv_obj_clear_flag(object, LV_OBJ_FLAG_SCROLLABLE);
    return object;
}

lv_obj_t* make_positioned_dial_image(
    lv_obj_t* parent,
    const lv_image_dsc_t* image,
    int x,
    int y)
{
    lv_obj_t* object = lv_image_create(parent);
    lv_image_set_src(object, image);
    lv_obj_set_pos(object, x, y);
    lv_obj_clear_flag(object, LV_OBJ_FLAG_SCROLLABLE);
    return object;
}

void init_dial_images()
{
    init_image_descriptor(
        &kDialBaseplateImage,
        dial_baseplate_rgb565a8_start,
        dial_baseplate_rgb565a8_end,
        kDialBaseplateImageWidth,
        kDialBaseplateImageHeight,
        kDialBaseplateImageStride);
}

}  // namespace

void RotaryDialScene::create(lv_obj_t* parent)
{
    destroy();
    parent_ = parent;
    if (parent_ == nullptr) {
        return;
    }

    init_dial_images();
    base_image_ = make_centered_dial_image(parent_, &kDialBaseplateImage);
    const size_t pixel_count = static_cast<size_t>(kDialFrameImageWidth) *
                               static_cast<size_t>(kDialFrameImageHeight);
    dial_frame_index_buffer_ = static_cast<uint8_t*>(
        heap_caps_malloc(pixel_count, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    dial_frame_rgb565_buffer_ = static_cast<uint8_t*>(
        heap_caps_malloc(pixel_count * 2U, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    dial_frame_decompressor_ = heap_caps_malloc(
        sizeof(lgfx_tinfl_decompressor),
        MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (dial_frame_decompressor_ == nullptr) {
        dial_frame_decompressor_ = heap_caps_malloc(
            sizeof(lgfx_tinfl_decompressor),
            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
    if (dial_frame_index_buffer_ != nullptr && dial_frame_rgb565_buffer_ != nullptr &&
        dial_frame_decompressor_ != nullptr) {
        init_image_descriptor(
            &dial_frame_dsc_,
            dial_frame_rgb565_buffer_,
            dial_frame_rgb565_buffer_ + pixel_count * 2U,
            kDialFrameImageWidth,
            kDialFrameImageHeight,
            kDialFrameImageStride,
            LV_COLOR_FORMAT_RGB565);
        dial_frame_ready_ = render_indexed_frame(
            dial_frame_index_buffer_,
            dial_frame_rgb565_buffer_,
            static_cast<lgfx_tinfl_decompressor*>(dial_frame_decompressor_),
            0);
        if (dial_frame_ready_) {
            dial_image_ = make_positioned_dial_image(
                parent_,
                &dial_frame_dsc_,
                kDialFrameImageX,
                kDialFrameImageY);
            rendered_frame_index_ = 0;
        }
    }
}

void RotaryDialScene::destroy()
{
    parent_ = nullptr;
    base_image_ = nullptr;
    dial_image_ = nullptr;
    if (dial_frame_index_buffer_ != nullptr) {
        heap_caps_free(dial_frame_index_buffer_);
        dial_frame_index_buffer_ = nullptr;
    }
    if (dial_frame_rgb565_buffer_ != nullptr) {
        heap_caps_free(dial_frame_rgb565_buffer_);
        dial_frame_rgb565_buffer_ = nullptr;
    }
    if (dial_frame_decompressor_ != nullptr) {
        heap_caps_free(dial_frame_decompressor_);
        dial_frame_decompressor_ = nullptr;
    }
    dial_frame_dsc_ = {};
    rotation_degrees_ = 0.0F;
    rendered_rotation_degrees_ = 0.0F;
    rendered_frame_index_ = -1;
    dial_frame_ready_ = false;
}

void RotaryDialScene::reset()
{
    set_rotation_degrees(0.0F, true);
}

void RotaryDialScene::set_visible(bool visible)
{
    lv_obj_t* objects[] = {base_image_, dial_image_};
    for (lv_obj_t* object : objects) {
        if (object == nullptr) {
            continue;
        }
        if (visible) {
            lv_obj_remove_flag(object, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(object, LV_OBJ_FLAG_HIDDEN);
        }
    }
}

int RotaryDialScene::digit_at_point(int x, int y) const
{
    int nearest_digit = -1;
    int nearest_distance_squared = kDigitHitRadius * kDigitHitRadius + 1;
    for (size_t index = 0; index < 10; ++index) {
        const int dx = x - kDigitPositions[index].x;
        const int dy = y - kDigitPositions[index].y;
        const int distance_squared = dx * dx + dy * dy;
        if (distance_squared <= kDigitHitRadius * kDigitHitRadius &&
            distance_squared < nearest_distance_squared) {
            nearest_digit = kDigitPositions[index].digit;
            nearest_distance_squared = distance_squared;
        }
    }
    return nearest_digit;
}

bool RotaryDialScene::digit_reached_stop(char digit) const
{
    const float stop_rotation = stop_rotation_for_digit(digit);
    const int stop_frame_index = frame_index_for_degrees(stop_rotation);
    const int current_frame_index = frame_index_for_degrees(rotation_degrees_);
    return stop_rotation > 0.0F &&
           (current_frame_index >= stop_frame_index ||
            rotation_degrees_ >= stop_rotation - kDialStopCommitToleranceDegrees);
}

void RotaryDialScene::advance_clockwise_from_touch(int previous_x, int previous_y, int x, int y, char digit)
{
    const float previous_angle = point_angle_degrees(previous_x, previous_y);
    const float current_angle = point_angle_degrees(x, y);
    const float delta = normalize_angle_delta(current_angle - previous_angle);
    if (delta <= 0.0F) {
        return;
    }

    float next = rotation_degrees_ + delta;
    const float stop_rotation = stop_rotation_for_digit(digit);
    if (stop_rotation <= 0.0F) {
        return;
    }
    if (next > stop_rotation) {
        next = stop_rotation;
    }
    set_rotation_degrees(next);
}

void RotaryDialScene::set_rotation_degrees(float degrees, bool force_render)
{
    rotation_degrees_ = degrees;
    if (dial_image_ == nullptr) {
        return;
    }

    if (!force_render && fabsf(rotation_degrees_ - rendered_rotation_degrees_) < kDialRenderStepDegrees) {
        return;
    }
    if (!dial_frame_ready_ || dial_frame_index_buffer_ == nullptr || dial_frame_rgb565_buffer_ == nullptr ||
        dial_frame_decompressor_ == nullptr) {
        return;
    }
    const int frame_index = frame_index_for_degrees(rotation_degrees_);
    if (frame_index == rendered_frame_index_) {
        rendered_rotation_degrees_ = rotation_degrees_;
        return;
    }
    if (!render_indexed_frame(
            dial_frame_index_buffer_,
            dial_frame_rgb565_buffer_,
            static_cast<lgfx_tinfl_decompressor*>(dial_frame_decompressor_),
            frame_index)) {
        return;
    }
    lv_obj_invalidate(dial_image_);
    rendered_frame_index_ = frame_index;
    rendered_rotation_degrees_ = rotation_degrees_;
}

}  // namespace stopwatch_target
