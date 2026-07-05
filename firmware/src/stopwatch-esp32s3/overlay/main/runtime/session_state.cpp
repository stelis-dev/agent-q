#include "session_state.h"

#include <stdio.h>
#include <string.h>

namespace stopwatch_target {
namespace {

struct SessionState {
    char id[kSessionIdSize] = {};

    bool active() const
    {
        return id[0] != '\0';
    }
};

SessionState g_session;

}  // namespace

void session_state_init()
{
    session_state_clear();
}

bool session_state_active()
{
    return g_session.active();
}

const char* session_state_id()
{
    return g_session.id;
}

void session_state_clear()
{
    g_session.id[0] = '\0';
}

SessionStartResult session_state_replace(SessionRandomFn random_fn, void* random_context)
{
    char next_id[kSessionIdSize] = {};
    if (!signing::session_id_format_from_random(
            random_fn,
            random_context,
            next_id,
            sizeof(next_id))) {
        return SessionStartResult::rng_error;
    }
    snprintf(g_session.id, sizeof(g_session.id), "%s", next_id);
    return SessionStartResult::ok;
}

SessionValidationResult session_state_validate(const char* requested_session_id)
{
    if (!session_id_format_valid(requested_session_id)) {
        return SessionValidationResult::invalid_format;
    }
    if (!g_session.active()) {
        session_state_clear();
        return SessionValidationResult::missing;
    }
    if (strcmp(requested_session_id, g_session.id) != 0) {
        return SessionValidationResult::mismatch;
    }
    return SessionValidationResult::ok;
}

}  // namespace stopwatch_target
