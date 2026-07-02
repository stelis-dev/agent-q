#pragma once

#include "drawing_surface.h"
#include "local_pin_auth.h"
#include "modal_drawing.h"
#include "sui_zklogin_proposal_flow.h"
#include "timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class SuiZkLoginReviewPinBeginStatus {
    started,
    timed_out,
    unavailable,
    pin_unavailable,
};

struct SuiZkLoginReviewPinBeginResult {
    SuiZkLoginReviewPinBeginStatus status;
    SuiZkLoginProposalTerminalResult terminal_result;
};

struct SuiZkLoginReviewUiFlowOps {
    TickType_t (*now)();
    SuiZkLoginProposalSnapshot (*snapshot)();
    bool (*draw_review_panel)(
        const SuiZkLoginReviewViewModel& model,
        TimeoutWindow window);
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*review_panel_active)();
    void (*identification_display_clear)();
    SuiZkLoginReviewPinBeginResult (*begin_pin_from_review)(
        const SuiZkLoginProposalSnapshot& current,
        TickType_t now);
    bool (*draw_local_pin_auth_panel)(const char* notice);
    void (*wipe_local_pin_auth_scratch)(const char* reason);
    bool (*review_deadline_reached)(TickType_t now);
    SuiZkLoginProposalTerminalResult (*record_timed_out)();
    SuiZkLoginProposalTerminalResult (*record_rejected)();
    SuiZkLoginProposalTerminalResult (*record_ui_error)();
    void (*finish_terminal)(
        const char* request_id,
        SuiZkLoginProposalTerminalResult result);
    void (*finish_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
};

bool sui_zklogin_review_ui_show(const SuiZkLoginReviewUiFlowOps& ops);
void sui_zklogin_review_ui_continue(const SuiZkLoginReviewUiFlowOps& ops);
void sui_zklogin_review_ui_reject(const SuiZkLoginReviewUiFlowOps& ops);
void sui_zklogin_review_ui_clear_if_needed(const SuiZkLoginReviewUiFlowOps& ops);

}  // namespace signing
