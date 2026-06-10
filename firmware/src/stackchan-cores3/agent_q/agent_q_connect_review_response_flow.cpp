#include "agent_q_connect_review_response_flow.h"

#include "agent_q_request_id.h"

namespace agent_q {

namespace {

void log_info(
    const AgentQConnectReviewResponseFlowOps& ops,
    const char* message,
    const char* id)
{
    if (ops.log_info != nullptr) {
        ops.log_info(message, id);
    }
}

void log_error(
    const AgentQConnectReviewResponseFlowOps& ops,
    const char* message,
    const char* id)
{
    if (ops.log_error != nullptr) {
        ops.log_error(message, id);
    }
}

void log_write_failure(
    const AgentQConnectReviewResponseFlowOps& ops,
    const char* response_type,
    const char* id)
{
    if (ops.log_write_failure != nullptr) {
        ops.log_write_failure(response_type, id);
    }
}

void log_review_recovered(
    const AgentQConnectReviewResponseFlowOps& ops,
    const char* id)
{
    if (ops.log_review_recovered != nullptr) {
        ops.log_review_recovered(id);
    }
}

void show_result_and_clear_review(
    const AgentQConnectReviewResponseFlowOps& ops,
    const char* message,
    AgentQMessageKind kind)
{
    if (ops.show_result_and_clear_review != nullptr) {
        ops.show_result_and_clear_review(message, kind);
    }
}

TickType_t current_tick(const AgentQConnectReviewResponseFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

bool local_pin_flow_active(const AgentQConnectReviewResponseFlowOps& ops)
{
    return ops.local_pin_flow_active != nullptr && ops.local_pin_flow_active();
}

void reset_connect_choices(const AgentQConnectReviewResponseFlowOps& ops)
{
    if (ops.reset_connect_choices != nullptr) {
        ops.reset_connect_choices();
    }
}

void drain_connect_review_choice_events(
    const AgentQConnectReviewResponseFlowOps& ops)
{
    if (local_pin_flow_active(ops)) {
        reset_connect_choices(ops);
        return;
    }

    AgentQConnectApprovalChoice choice = AgentQConnectApprovalChoice::none;
    while (ops.receive_connect_choice != nullptr &&
           ops.receive_connect_choice(&choice)) {
        if (ops.awaiting_choice == nullptr || !ops.awaiting_choice()) {
            continue;
        }

        const TickType_t now = current_tick(ops);
        if (choice == AgentQConnectApprovalChoice::approved &&
            ops.human_approval_requires_pin != nullptr &&
            ops.human_approval_requires_pin()) {
            if (ops.begin_pin_auth_from_review != nullptr) {
                ops.begin_pin_auth_from_review(now);
            }
            reset_connect_choices(ops);
            return;
        }
        if (ops.choose != nullptr) {
            ops.choose(choice, now);
        }
        reset_connect_choices(ops);
        return;
    }
}

void send_connect_terminal_response_if_needed(
    const AgentQConnectReviewResponseFlowOps& ops)
{
    const AgentQConnectApprovalSnapshot approval =
        ops.snapshot != nullptr ? ops.snapshot() : AgentQConnectApprovalSnapshot{};
    if (!approval.active || approval.choice == AgentQConnectApprovalChoice::none) {
        if (local_pin_flow_active(ops)) {
            return;
        }
        if (ops.deadline_reached != nullptr &&
            ops.deadline_reached(current_tick(ops))) {
            char request_id[kAgentQRequestIdSize] = {};
            if (ops.request_id != nullptr) {
                ops.request_id(request_id, sizeof(request_id));
            }
            if (ops.clear_approval != nullptr) {
                ops.clear_approval();
            }
            if (ops.write_rejected != nullptr) {
                ops.write_rejected(
                    request_id,
                    "timeout",
                    "Connection approval timed out.");
            }
            log_info(ops, "connect timed out", request_id);
            show_result_and_clear_review(
                ops,
                "Connection timed out",
                AgentQMessageKind::timeout);
        }
        return;
    }

    const bool approved = approval.choice == AgentQConnectApprovalChoice::approved;
    char request_id[kAgentQRequestIdSize] = {};
    if (ops.request_id != nullptr) {
        ops.request_id(request_id, sizeof(request_id));
    }
    if (ops.clear_approval != nullptr) {
        ops.clear_approval();
    }
    if (approved) {
        if (ops.replace_active_session == nullptr ||
            !ops.replace_active_session()) {
            if (ops.write_error != nullptr) {
                ops.write_error(
                    request_id,
                    "rng_error",
                    "Could not create session id.");
            }
            log_error(ops, "connect could not create session id", request_id);
            show_result_and_clear_review(ops, "RNG error", AgentQMessageKind::error);
            return;
        }
        if (ops.write_approved != nullptr && ops.write_approved(request_id)) {
            log_info(ops, "connect approved", request_id);
        } else {
            log_write_failure(ops, "connect_result", request_id);
        }
        show_result_and_clear_review(ops, "Connected", AgentQMessageKind::success);
        return;
    }

    if (ops.write_rejected != nullptr &&
        ops.write_rejected(request_id, "rejected", "Connection rejected.")) {
        log_info(ops, "connect rejected", request_id);
    } else {
        log_write_failure(ops, "connect_result", request_id);
    }
    show_result_and_clear_review(
        ops,
        "Connection rejected",
        AgentQMessageKind::rejected);
}

void ensure_connect_review_ui(const AgentQConnectReviewResponseFlowOps& ops)
{
    if (ops.awaiting_choice == nullptr || !ops.awaiting_choice()) {
        return;
    }
    if (local_pin_flow_active(ops)) {
        return;
    }
    if (ops.review_panel_visible != nullptr && ops.review_panel_visible()) {
        return;
    }

    const AgentQConnectApprovalSnapshot approval =
        ops.snapshot != nullptr ? ops.snapshot() : AgentQConnectApprovalSnapshot{};
    if (ops.show_review != nullptr) {
        ops.show_review();
    }
    log_review_recovered(ops, approval.request_id);
}

}  // namespace

void connect_review_response_flow_run(
    const AgentQConnectReviewResponseFlowOps& ops)
{
    drain_connect_review_choice_events(ops);
    send_connect_terminal_response_if_needed(ops);
    ensure_connect_review_ui(ops);
}

}  // namespace agent_q
