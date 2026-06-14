#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = resolve(repoRoot, "specs/sui-sign-transaction-policy-contract.tsv");

const outputs = {
  coreTs: resolve(repoRoot, "packages/core/src/sui-policy-contract.ts"),
  firmwareCommon: resolve(
    repoRoot,
    "firmware/src/common/agent_q/policy/agent_q_policy_contract.generated.h",
  ),
  firmwareSui: resolve(
    repoRoot,
    "firmware/src/common/agent_q/sui/agent_q_sui_policy_contract.generated.h",
  ),
};

const validValueTypes = new Set(["string", "u64_decimal"]);
const validBooleans = new Set(["yes", "no"]);
const fieldPattern = /^[a-z][a-z0-9_]*(\.[a-z0-9_{}]+)+$/;

function fail(message) {
  throw new Error(message);
}

function parseBoolean(value, lineNumber) {
  if (!validBooleans.has(value)) {
    fail(`Invalid boolean token "${value}" on line ${lineNumber}`);
  }
  return value === "yes";
}

function requireFieldName(value, lineNumber) {
  if (!fieldPattern.test(value)) {
    fail(`Invalid field name "${value}" on line ${lineNumber}`);
  }
}

function requireValueType(value, lineNumber) {
  if (!validValueTypes.has(value)) {
    fail(`Invalid value type "${value}" on line ${lineNumber}`);
  }
}

function parseManifest(text) {
  const explicitFields = [];
  const generatedFields = [];
  const generated2Fields = [];
  const signBounds = [];

  for (const [lineIndex, rawLine] of text.split(/\r?\n/).entries()) {
    const lineNumber = lineIndex + 1;
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const parts = line.split("\t");
    const kind = parts[0];

    if (kind === "field") {
      if (parts.length !== 6) {
        fail(`field row must have 6 columns on line ${lineNumber}`);
      }
      const [, field, type, allowEq, allowIn, allowLte] = parts;
      requireFieldName(field, lineNumber);
      requireValueType(type, lineNumber);
      explicitFields.push({
        field,
        type,
        allowEq: parseBoolean(allowEq, lineNumber),
        allowIn: parseBoolean(allowIn, lineNumber),
        allowLte: parseBoolean(allowLte, lineNumber),
      });
      continue;
    }

    if (kind === "generated") {
      if (parts.length !== 7) {
        fail(`generated row must have 7 columns on line ${lineNumber}`);
      }
      const [, pattern, countText, type, allowEq, allowIn, allowLte] = parts;
      requireFieldName(pattern, lineNumber);
      requireValueType(type, lineNumber);
      if ((pattern.match(/\{\}/g) ?? []).length !== 1) {
        fail(`generated pattern must contain one placeholder on line ${lineNumber}`);
      }
      const count = Number.parseInt(countText, 10);
      if (!Number.isSafeInteger(count) || count <= 0) {
        fail(`generated count must be a positive integer on line ${lineNumber}`);
      }
      generatedFields.push({
        pattern,
        count,
        type,
        allowEq: parseBoolean(allowEq, lineNumber),
        allowIn: parseBoolean(allowIn, lineNumber),
        allowLte: parseBoolean(allowLte, lineNumber),
      });
      continue;
    }

    if (kind === "generated2") {
      if (parts.length !== 8) {
        fail(`generated2 row must have 8 columns on line ${lineNumber}`);
      }
      const [, pattern, outerCountText, innerCountText, type, allowEq, allowIn, allowLte] = parts;
      requireFieldName(pattern, lineNumber);
      requireValueType(type, lineNumber);
      if ((pattern.match(/\{\}/g) ?? []).length !== 2) {
        fail(`generated2 pattern must contain two placeholders on line ${lineNumber}`);
      }
      const outerCount = Number.parseInt(outerCountText, 10);
      const innerCount = Number.parseInt(innerCountText, 10);
      if (!Number.isSafeInteger(outerCount) || outerCount <= 0 ||
          !Number.isSafeInteger(innerCount) || innerCount <= 0) {
        fail(`generated2 counts must be positive integers on line ${lineNumber}`);
      }
      generated2Fields.push({
        pattern,
        outerCount,
        innerCount,
        type,
        allowEq: parseBoolean(allowEq, lineNumber),
        allowIn: parseBoolean(allowIn, lineNumber),
        allowLte: parseBoolean(allowLte, lineNumber),
      });
      continue;
    }

    if (kind === "sign_eq") {
      if (parts.length !== 3) {
        fail(`sign_eq row must have 3 columns on line ${lineNumber}`);
      }
      requireFieldName(parts[1], lineNumber);
      signBounds.push({ kind: "eq", field: parts[1], value: parts[2] });
      continue;
    }

    if (kind === "sign_string" || kind === "sign_string_eq" || kind === "sign_lte") {
      if (parts.length !== 2) {
        fail(`${kind} row must have 2 columns on line ${lineNumber}`);
      }
      requireFieldName(parts[1], lineNumber);
      signBounds.push({
        kind: kind.replace(/^sign_/, ""),
        field: parts[1],
      });
      continue;
    }

    fail(`Unknown manifest row kind "${kind}" on line ${lineNumber}`);
  }

  const fields = [
    ...explicitFields,
    ...generatedFields.flatMap((entry) =>
      Array.from({ length: entry.count }, (_, index) => ({
        field: entry.pattern.replace("{}", String(index)),
        type: entry.type,
        allowEq: entry.allowEq,
        allowIn: entry.allowIn,
        allowLte: entry.allowLte,
      })),
    ),
    ...generated2Fields.flatMap((entry) =>
      Array.from({ length: entry.outerCount }, (_, outerIndex) =>
        Array.from({ length: entry.innerCount }, (_, innerIndex) => ({
          field: entry.pattern.replace("{}", String(outerIndex)).replace("{}", String(innerIndex)),
          type: entry.type,
          allowEq: entry.allowEq,
          allowIn: entry.allowIn,
          allowLte: entry.allowLte,
        })),
      ).flat(),
    ),
  ];

  const seenFields = new Set();
  for (const field of fields) {
    if (seenFields.has(field.field)) {
      fail(`Duplicate policy field in manifest: ${field.field}`);
    }
    seenFields.add(field.field);
  }
  for (const bound of signBounds) {
    if (!seenFields.has(bound.field)) {
      fail(`Sign-rule bound references unknown policy field: ${bound.field}`);
    }
  }

  return {
    explicitFields,
    generatedFields,
    generated2Fields,
    fields,
    commonFields: fields.filter((field) => field.field.startsWith("common.")),
    suiFields: fields.filter((field) => !field.field.startsWith("common.")),
    signBounds,
  };
}

function tsDescriptor(field) {
  return `"${field.field}": { type: "${field.type}", allowEq: ${field.allowEq}, allowIn: ${field.allowIn}, allowLte: ${field.allowLte} }`;
}

function renderCoreTs(contract) {
  const commonLines = contract.commonFields.map((field) => `  ${tsDescriptor(field)},`).join("\n");
  const suiLines = contract.suiFields.map((field) => `  ${tsDescriptor(field)},`).join("\n");
  const signBounds = contract.signBounds.map((bound) => {
    const value = bound.value === undefined ? "" : `, value: ${JSON.stringify(bound.value)}`;
    return `  { kind: "${bound.kind}", field: "${bound.field}"${value} },`;
  }).join("\n");

  return `export type PolicyValueType = "string" | "u64_decimal";
export type SignRuleBoundKind = "eq" | "string" | "string_eq" | "lte";

export interface PolicyFieldDescriptor {
  type: PolicyValueType;
  allowEq: boolean;
  allowIn: boolean;
  allowLte: boolean;
}

export interface SignRuleBound {
  kind: SignRuleBoundKind;
  field: string;
  value?: string;
}

// Generated from specs/sui-sign-transaction-policy-contract.tsv.
// Do not edit by hand. Run npm run generate:sui-policy-contract.
// Firmware remains the signing authority; this is the Core sanitizer projection.
export const COMMON_POLICY_FIELDS: Record<string, PolicyFieldDescriptor> = {
${commonLines}
};

export const SUI_SIGN_TRANSACTION_POLICY_FIELDS: Record<string, PolicyFieldDescriptor> = {
${suiLines}
};

export const SUI_CURRENT_SIGN_RULE_BOUNDS: readonly SignRuleBound[] = [
${signBounds}
];
`;
}

function cppString(value) {
  return JSON.stringify(value);
}

function cppBool(value) {
  return value ? "true" : "false";
}

function cppValueType(type) {
  if (type === "string") {
    return "AgentQPolicyValueType::string";
  }
  if (type === "u64_decimal") {
    return "AgentQPolicyValueType::u64_decimal";
  }
  fail(`Unsupported C++ policy value type: ${type}`);
}

function cppDescriptor(field) {
  return `    {${cppString(field.field)}, ${cppValueType(field.type)}, ${cppBool(field.allowEq)}, ${cppBool(field.allowIn)}, ${cppBool(field.allowLte)}},`;
}

function renderFirmwareCommon(contract) {
  return `#pragma once

// Generated from specs/sui-sign-transaction-policy-contract.tsv.
// Do not edit by hand. Run npm run generate:sui-policy-contract.

static_assert(
    kAgentQPolicyCommonFieldDescriptorCount == ${contract.commonFields.length},
    "Common policy field descriptor count must match the shared policy contract");

const AgentQPolicyFieldDescriptor
    kAgentQPolicyCommonFieldDescriptors[kAgentQPolicyCommonFieldDescriptorCount] = {
${contract.commonFields.map(cppDescriptor).join("\n")}
    };
`;
}

const generatedPatternNames = new Map([
  ["sui.command{}_kind", "kCommandKindFields"],
  ["sui.command{}_move_call_package", "kCommandMoveCallPackageFields"],
  ["sui.command{}_move_call_module", "kCommandMoveCallModuleFields"],
  ["sui.command{}_move_call_function", "kCommandMoveCallFunctionFields"],
  ["sui.command{}_move_call_type_args", "kCommandMoveCallTypeArgCountFields"],
]);

function generatedFieldsByPattern(contract, pattern) {
  const entry = contract.generatedFields.find((candidate) => candidate.pattern === pattern);
  if (entry === undefined) {
    fail(`Missing required generated field pattern: ${pattern}`);
  }
  return Array.from({ length: entry.count }, (_, index) => entry.pattern.replace("{}", String(index)));
}

function renderOneDimensionalFieldArray(name, fields) {
  return `constexpr const char* ${name}[kSuiPolicyFactMaxCommands] = {
${fields.map((field) => `    ${cppString(field)},`).join("\n")}
};
`;
}

function renderTypeArgFieldArray(contract) {
  const entry = contract.generated2Fields.find(
    (candidate) => candidate.pattern === "sui.command{}_move_call_type_arg{}",
  );
  if (entry === undefined) {
    fail("Missing required generated2 type-argument pattern");
  }
  const rows = Array.from({ length: entry.outerCount }, (_, outerIndex) => {
    const inner = Array.from(
      { length: entry.innerCount },
      (_, innerIndex) => `            ${cppString(entry.pattern.replace("{}", String(outerIndex)).replace("{}", String(innerIndex)))},`,
    ).join("\n");
    return `        {\n${inner}\n        },`;
  }).join("\n");
  return `constexpr const char* kCommandMoveCallTypeArgFields
    [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxTypeArguments] = {
${rows}
    };
`;
}

function cppBoundKind(kind) {
  switch (kind) {
    case "eq":
      return "SuiRequiredSignBoundKind::eq";
    case "string":
      return "SuiRequiredSignBoundKind::string";
    case "string_eq":
      return "SuiRequiredSignBoundKind::string_eq";
    case "lte":
      return "SuiRequiredSignBoundKind::lte";
    default:
      fail(`Unsupported sign bound kind: ${kind}`);
  }
}

function renderFirmwareSui(contract) {
  const generatedCounts = new Set(contract.generatedFields.map((entry) => entry.count));
  if (generatedCounts.size !== 1) {
    fail("All one-dimensional generated Sui policy fields must share one command count");
  }
  const commandCount = [...generatedCounts][0];
  const typeArgEntry = contract.generated2Fields.find(
    (entry) => entry.pattern === "sui.command{}_move_call_type_arg{}",
  );
  if (typeArgEntry === undefined) {
    fail("Missing Sui MoveCall type-argument generated2 contract row");
  }
  if (typeArgEntry.outerCount !== commandCount) {
    fail("MoveCall type-argument outer count must match command count");
  }

  const fieldArrays = [...generatedPatternNames.entries()].map(([pattern, name]) =>
    renderOneDimensionalFieldArray(name, generatedFieldsByPattern(contract, pattern)),
  ).join("\n");
  const bounds = contract.signBounds.map((bound) => {
    const value = bound.value === undefined ? "nullptr" : cppString(bound.value);
    return `    {${cppBoundKind(bound.kind)}, ${cppString(bound.field)}, ${value}},`;
  }).join("\n");

  return `#pragma once

// Generated from specs/sui-sign-transaction-policy-contract.tsv.
// Do not edit by hand. Run npm run generate:sui-policy-contract.

static_assert(
    kSuiPolicyFactMaxCommands == ${commandCount},
    "Sui policy command field count must match the shared policy contract");
static_assert(
    kSuiPolicyFactMaxTypeArguments == ${typeArgEntry.innerCount},
    "Sui policy MoveCall type-argument field count must match the shared policy contract");

${fieldArrays}
${renderTypeArgFieldArray(contract)}

constexpr AgentQPolicyFieldDescriptor kSuiSignTransactionPolicyFields[] = {
${contract.suiFields.map(cppDescriptor).join("\n")}
};

static_assert(
    sizeof(kSuiSignTransactionPolicyFields) / sizeof(kSuiSignTransactionPolicyFields[0]) <=
        kAgentQPolicyMaxFieldDescriptors,
    "Sui sign_transaction policy descriptor count exceeds policy capacity");

constexpr SuiRequiredSignBound kSuiSignTransactionRequiredSignBounds[] = {
${bounds}
};
`;
}

function readExpectedOutputs() {
  const contract = parseManifest(readFileSync(manifestPath, "utf8"));
  return new Map([
    [outputs.coreTs, renderCoreTs(contract)],
    [outputs.firmwareCommon, renderFirmwareCommon(contract)],
    [outputs.firmwareSui, renderFirmwareSui(contract)],
  ]);
}

function writeOutputs(expectedOutputs) {
  for (const [path, content] of expectedOutputs) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, "utf8");
  }
}

function checkOutputs(expectedOutputs) {
  const stale = [];
  for (const [path, expected] of expectedOutputs) {
    let actual = "";
    try {
      actual = readFileSync(path, "utf8");
    } catch {
      stale.push(path);
      continue;
    }
    if (actual !== expected) {
      stale.push(path);
    }
  }
  if (stale.length > 0) {
    for (const path of stale) {
      console.error(`Stale generated policy contract output: ${relative(repoRoot, path)}`);
    }
    console.error("Run npm run generate:sui-policy-contract");
    process.exit(1);
  }
}

const args = new Set(process.argv.slice(2));
if (args.size > 1 || (args.size === 1 && !args.has("--check"))) {
  console.error("Usage: tools/generate_sui_policy_contract.mjs [--check]");
  process.exit(2);
}

const expectedOutputs = readExpectedOutputs();
if (args.has("--check")) {
  checkOutputs(expectedOutputs);
} else {
  writeOutputs(expectedOutputs);
}
