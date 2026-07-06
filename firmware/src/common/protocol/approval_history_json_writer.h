#pragma once

#include <ArduinoJson.h>

#include "protocol/approval_history.h"

namespace signing {

bool approval_history_write_page_json(JsonObject result, const ApprovalHistoryPage& page);

}  // namespace signing
