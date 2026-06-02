#include "agent_q_avatar_overlay_drawing.h"

#include <memory>

#include "agent_q_display_power.h"
#include "agent_q_motion_state.h"
#include "agent_q_speech_bubble.h"
#include "hal/hal.h"
#include "stackchan/stackchan.h"

namespace agent_q {

namespace {

struct AgentQMessagePresentation {
    lv_color_t background;
    lv_color_t foreground;
    stackchan::avatar::Emotion emotion = stackchan::avatar::Emotion::Neutral;
    bool lift_head = false;
};

struct AgentQAvatarOverlayState {
    stackchan::avatar::Avatar* speech_avatar = nullptr;
    int speech_decorator_id = -1;
    AgentQUiMode speech_mode = AgentQUiMode::none;
    stackchan::avatar::Emotion previous_emotion = stackchan::avatar::Emotion::Neutral;
    bool owns_emotion = false;
    TickType_t message_deadline = 0;
};

AgentQAvatarOverlayState g_overlay;

AgentQMessagePresentation message_presentation(AgentQMessageKind kind)
{
    switch (kind) {
        case AgentQMessageKind::approval:
            return {
                lv_color_hex(0xFFD166), lv_color_hex(0x3A2B00), stackchan::avatar::Emotion::Neutral, true};
        case AgentQMessageKind::success:
            return {
                lv_color_hex(0x7DE2A6), lv_color_hex(0x063A1D), stackchan::avatar::Emotion::Happy, true};
        case AgentQMessageKind::rejected:
            return {
                lv_color_hex(0xF28B82), lv_color_hex(0x3C0505), stackchan::avatar::Emotion::Sad, false};
        case AgentQMessageKind::timeout:
            return {
                lv_color_hex(0xD0D5DD), lv_color_hex(0x2B2D33), stackchan::avatar::Emotion::Sleepy, false};
        case AgentQMessageKind::error:
            return {
                lv_color_hex(0xE25B5B), lv_color_hex(0xFFFFFF), stackchan::avatar::Emotion::Angry, false};
        case AgentQMessageKind::usb_connected:
            return {
                lv_color_hex(0x7DE2A6), lv_color_hex(0x063A1D), stackchan::avatar::Emotion::Happy, true};
        case AgentQMessageKind::usb_disconnected:
            return {
                lv_color_hex(0xB9C0CC), lv_color_hex(0x243040), stackchan::avatar::Emotion::Sad, false};
        case AgentQMessageKind::info:
        default:
            return {
                lv_color_hex(0x91D8FF), lv_color_hex(0x05324A), stackchan::avatar::Emotion::Doubt, true};
    }
}

}  // namespace

void avatar_overlay_clear()
{
    if (g_overlay.speech_avatar == nullptr) {
        g_overlay.speech_mode = AgentQUiMode::none;
        g_overlay.speech_decorator_id = -1;
        g_overlay.message_deadline = 0;
        return;
    }

    auto* speech_avatar = g_overlay.speech_avatar;
    LvglLockGuard lock;
    if (GetStackChan().hasAvatar()) {
        auto& current_avatar = GetStackChan().avatar();
        if (&current_avatar == speech_avatar) {
            if (g_overlay.speech_decorator_id >= 0) {
                current_avatar.removeDecorator(g_overlay.speech_decorator_id);
            }
            if (g_overlay.owns_emotion) {
                current_avatar.setEmotion(g_overlay.previous_emotion);
            }
        }
    }
    g_overlay.speech_avatar = nullptr;
    g_overlay.speech_decorator_id = -1;
    g_overlay.speech_mode = AgentQUiMode::none;
    g_overlay.owns_emotion = false;
    g_overlay.message_deadline = 0;
}

bool avatar_overlay_show_message(
    const char* message,
    AgentQMessageKind kind,
    AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback)
{
    avatar_overlay_clear();
    if (message == nullptr || message[0] == '\0') {
        return false;
    }

    LvglLockGuard lock;
    request_display_power_wake();
    if (!GetStackChan().hasAvatar()) {
        return false;
    }
    auto& avatar = GetStackChan().avatar();
    const AgentQMessagePresentation presentation = message_presentation(kind);
    g_overlay.previous_emotion = avatar.getEmotion();
    g_overlay.owns_emotion = true;
    avatar.setEmotion(presentation.emotion);
    g_overlay.speech_decorator_id = avatar.addDecorator(std::make_unique<AgentQSpeechBubbleDecorator>(
        lv_screen_active(),
        message != nullptr && message[0] != '\0' ? message : "Agent-Q",
        presentation.background,
        presentation.foreground,
        click_callback));
    if (presentation.lift_head) {
        play_motion_feedback(AgentQMotionFeedbackState::head_lift);
    }
    g_overlay.speech_avatar = &avatar;
    g_overlay.speech_mode = mode;
    g_overlay.message_deadline = duration_ms > 0 ? xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms) : 0;
    return g_overlay.speech_decorator_id >= 0;
}

AgentQUiMode avatar_overlay_mode()
{
    return g_overlay.speech_mode;
}

bool avatar_overlay_message_deadline_reached(TickType_t now)
{
    return g_overlay.message_deadline != 0 &&
           static_cast<int32_t>(now - g_overlay.message_deadline) >= 0;
}

}  // namespace agent_q
