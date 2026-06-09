import {
  HASH_ID_PATTERN,
  RULE_REF_PATTERN,
} from "./protocol-primitives.js";

export const AGENT_Q_POLICY_SCHEMA = "agentq.policy.v0";
export const POLICY_ID_PATTERN = HASH_ID_PATTERN;
export const MAX_POLICY_RULE_COUNT = 16;
export const MAX_POLICY_RULE_CRITERIA = 8;
export const MAX_POLICY_CRITERION_VALUES = 16;
export const MAX_POLICY_FIELD_ID_LENGTH = 48;
export const MAX_POLICY_RULE_ID_LENGTH = 32;
export const MAX_POLICY_CHAIN_ID_LENGTH = 32;
export const MAX_POLICY_METHOD_LENGTH = 64;
export const MAX_POLICY_VALUE_LENGTH = 96;
export const MAX_POLICY_UPDATE_REQUEST_JSON_BYTES = 4096;
export const MAX_APPROVAL_HISTORY_RECORDS = 4;
export const UINT_DECIMAL_STRING_PATTERN = /^(0|[1-9][0-9]{0,19})$/;
export const POLICY_ACTIONS = ["reject", "sign"] as const;
export const POLICY_OPERATORS = ["eq", "in", "lte"] as const;
export const POLICY_RULE_ID_PATTERN = /^[a-z][a-z0-9_.:/-]{0,31}$/;
export const POLICY_IDENTIFIER_PATTERN = /^[a-z0-9_.:/-]+$/;
export const POLICY_FIELD_ID_PATTERN = /^[a-z0-9_]+\.[a-z0-9_]+$/;
export const APPROVAL_HISTORY_REASON_CODE_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
export const APPROVAL_HISTORY_RULE_REF_PATTERN = RULE_REF_PATTERN;
export const SIGNING_HISTORY_RECORD_KINDS = [
  "confirmation",
  "terminal",
] as const;
export const SIGNING_HISTORY_TERMINAL_RESULTS = [
  "signed",
  "user_rejected",
  "user_timed_out",
  "policy_rejected",
  "signing_failed",
] as const;
export const APPROVAL_HISTORY_POLICY_UPDATE_RESULTS = [
  "applied",
  "rejected",
  "timed_out",
  "storage_error",
] as const;
export const APPROVAL_HISTORY_HIGHEST_ACTIONS = ["reject", "sign"] as const;
export const POLICY_PROPOSE_RESULT_STATUSES = [
  "applied",
  "rejected",
  "timed_out",
  "invalid_policy",
  "ui_error",
  "storage_error",
  "consistency_error",
] as const;
export const SIGN_CHAIN_PATTERN = /^[a-z][a-z0-9_.-]{0,31}$/;
export const SIGN_METHOD_PATTERN = /^[a-z][a-z0-9_.-]{0,63}$/;
