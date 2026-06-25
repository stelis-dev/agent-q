import {
  HASH_ID_PATTERN,
  RULE_REF_PATTERN,
  UINT_DECIMAL_STRING_PATTERN,
} from "./protocol-primitives.js";

export const AGENT_Q_POLICY_SCHEMA = "agentq.policy";
export const POLICY_ID_PATTERN = HASH_ID_PATTERN;
export const MAX_POLICY_BLOCKCHAINS = 4;
export const MAX_POLICY_NETWORKS_PER_BLOCKCHAIN = 8;
export const MAX_POLICY_POLICIES_PER_NETWORK = 16;
export const MAX_POLICY_CONDITIONS_PER_POLICY = 64;
export const MAX_POLICY_CONDITION_VALUES = 16;
export const MAX_POLICY_TOTAL_NETWORKS = 16;
export const MAX_POLICY_TOTAL_POLICIES = 64;
export const MAX_POLICY_TOTAL_CONDITIONS = 256;
export const MAX_POLICY_FIELD_ID_LENGTH = 64;
export const MAX_POLICY_ID_LENGTH = 32;
export const MAX_POLICY_BLOCKCHAIN_LENGTH = 32;
export const MAX_POLICY_NETWORK_LENGTH = 32;
export const MAX_POLICY_VALUE_LENGTH = 255;
export const MAX_POLICY_UPDATE_REQUEST_JSON_BYTES = 16384;
export const MAX_APPROVAL_HISTORY_RECORDS = 4;
export { UINT_DECIMAL_STRING_PATTERN };
export const POLICY_ACTIONS = ["reject", "sign"] as const;
export const POLICY_OPERATORS = [
  "eq",
  "in",
  "not_in",
  "lte",
  "contains",
  "not_contains",
  "all_in",
  "none_in",
] as const;
export const POLICY_ENTRY_ID_PATTERN = /^[a-z][a-z0-9_.:/-]{0,31}$/;
export const POLICY_FIELD_ID_PATTERN = /^[a-z0-9_]+(?:\.[a-z0-9_]+)+$/;
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
export const POLICY_PROPOSAL_OUTCOME_STATUSES = [
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
