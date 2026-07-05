import assert from "node:assert/strict";
import test from "node:test";
import {
  DEVICE_STATES,
  MAX_FIRMWARE_NAME_LENGTH,
  MAX_PORT_HINT_LENGTH,
  isDeviceState,
  isClientName,
  isIsoTimestamp,
  isSafeDeviceId,
  isSafeDisplayText,
  isSafeRequestId,
  isSessionId,
  isValidLabel,
  isValidPurpose,
  sanitizeDisplayText,
  sanitizePortHint,
} from "../dist/safe-text.js";

// Control characters are built from char codes so this source file never
// contains raw control bytes.
const NUL = String.fromCharCode(0);
const BEL = String.fromCharCode(7);
const TAB = String.fromCharCode(9);
const NL = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const DEL = String.fromCharCode(127);
const HIGH = String.fromCharCode(0xff); // non-ASCII (U+00FF)

const SAFE_UUID = "a508d833-5c83-4680-88bb-18aee976881e";

test("isSafeDeviceId accepts bounded id charset and rejects unsafe ids", () => {
  assert.equal(isSafeDeviceId(SAFE_UUID), true);
  assert.equal(isSafeDeviceId("dev_1.2-3"), true);
  assert.equal(isSafeDeviceId("a"), true);
  assert.equal(isSafeDeviceId("x".repeat(128)), true);
  assert.equal(isSafeDeviceId("x".repeat(129)), false);
  assert.equal(isSafeDeviceId(""), false);
  assert.equal(isSafeDeviceId("has space"), false);
  assert.equal(isSafeDeviceId("bad" + NL + "id"), false);
  assert.equal(isSafeDeviceId("a/b"), false);
  assert.equal(isSafeDeviceId(123), false);
  assert.equal(isSafeDeviceId(null), false);
});

test("isSafeRequestId enforces the bounded request-id charset", () => {
  assert.equal(isSafeRequestId("req_ok-1.2"), true);
  assert.equal(isSafeRequestId("req_" + "a".repeat(75)), true);
  assert.equal(isSafeRequestId("a".repeat(80)), false);
  assert.equal(isSafeRequestId("req/unsafe"), false);
  assert.equal(isSafeRequestId(""), false);
});

test("isSessionId requires the lowercase-hex session format", () => {
  assert.equal(isSessionId("session_abcdef01"), true);
  assert.equal(isSessionId("session_00010203040506070"), true);
  assert.equal(isSessionId("session_000102030405060700"), false);
  assert.equal(isSessionId("session_" + "a".repeat(128)), false);
  assert.equal(isSessionId("session_ABCDEF"), false);
  assert.equal(isSessionId("notsession_aa"), false);
  assert.equal(isSessionId("session_"), false);
  assert.equal(isSessionId(""), false);
});

test("isClientName accepts bounded printable ASCII and rejects control/high bytes", () => {
  assert.equal(isClientName("Agent-Q"), true);
  assert.equal(isClientName("x".repeat(64)), true);
  assert.equal(isClientName("x".repeat(65)), false);
  assert.equal(isClientName(""), false);
  assert.equal(isClientName("control" + TAB + "char"), false);
  assert.equal(isClientName("Hello " + HIGH), false);
});

test("isValidPurpose enforces charset and rejects reserved + prototype-sensitive names", () => {
  assert.equal(isValidPurpose("payment"), true);
  assert.equal(isValidPurpose("p1.0_a-b"), true);
  assert.equal(isValidPurpose("default"), false);
  assert.equal(isValidPurpose("with space"), false);
  assert.equal(isValidPurpose("x".repeat(33)), false);
  assert.equal(isValidPurpose(""), false);
  // Prototype-sensitive names match the charset but are unsafe as object keys.
  assert.equal(isValidPurpose("__proto__"), false, "__proto__ rejected");
  assert.equal(isValidPurpose("prototype"), false, "prototype rejected");
  assert.equal(isValidPurpose("constructor"), false, "constructor rejected");
});

test("isValidLabel allows printable display names and rejects control chars", () => {
  assert.equal(isValidLabel(null), true);
  assert.equal(isValidLabel("a"), true);
  assert.equal(isValidLabel("Desk device"), true);
  assert.equal(isValidLabel("x".repeat(64)), true);
  assert.equal(isValidLabel("x".repeat(65)), false);
  assert.equal(isValidLabel(""), false);
  assert.equal(isValidLabel("line" + NL + "break"), false);
  assert.equal(isValidLabel("tab" + TAB + "char"), false);
  assert.equal(isValidLabel("bell" + BEL), false);
  assert.equal(isValidLabel("del" + DEL), false);
  assert.equal(isValidLabel(123), false);
  // C1 controls and Unicode line/paragraph separators are rejected too...
  const C1 = String.fromCharCode(0x85);
  const LINE_SEP = String.fromCharCode(0x2028);
  const PARA_SEP = String.fromCharCode(0x2029);
  assert.equal(isValidLabel("a" + C1 + "b"), false, "C1 control rejected");
  assert.equal(isValidLabel("a" + LINE_SEP + "b"), false, "line separator rejected");
  assert.equal(isValidLabel("a" + PARA_SEP + "b"), false, "paragraph separator rejected");
  // ...but ordinary printable Unicode (CJK, accents) is allowed.
  assert.equal(isValidLabel("데스크 장치"), true, "CJK label allowed");
  assert.equal(isValidLabel("café"), true, "accented label allowed");
});

test("isDeviceState matches the protocol state enum", () => {
  for (const state of DEVICE_STATES) {
    assert.equal(isDeviceState(state), true);
  }
  assert.equal(isDeviceState("nope"), false);
  assert.equal(isDeviceState(""), false);
  assert.equal(isDeviceState(undefined), false);
});

test("isSafeDisplayText accepts bounded printable ASCII (including empty)", () => {
  assert.equal(isSafeDisplayText("ok", 64), true);
  assert.equal(isSafeDisplayText("", 64), true);
  assert.equal(isSafeDisplayText("Agent-Q Firmware", MAX_FIRMWARE_NAME_LENGTH), true);
  assert.equal(isSafeDisplayText("x".repeat(65), 64), false);
  assert.equal(isSafeDisplayText("a" + NL + "b", 64), false);
  assert.equal(isSafeDisplayText("a" + HIGH + "b", 64), false);
  assert.equal(isSafeDisplayText(123, 64), false);
});

test("isIsoTimestamp accepts valid ISO instants and rejects malformed ones", () => {
  assert.equal(isIsoTimestamp("2026-05-28T00:00:00.000Z"), true);
  assert.equal(isIsoTimestamp("2026-05-28T00:00:00Z"), true);
  assert.equal(isIsoTimestamp("2026-05-28T00:00:00+09:00"), true);
  assert.equal(isIsoTimestamp("2026-13-99T00:00:00Z"), false, "format ok but not a real date");
  assert.equal(isIsoTimestamp("not-a-date"), false);
  assert.equal(isIsoTimestamp("2026-05-28"), false);
  assert.equal(isIsoTimestamp(""), false);
});

test("sanitizeDisplayText strips non-printable bytes and caps length", () => {
  assert.equal(sanitizeDisplayText("a" + NL + "b" + TAB + "c" + CR, 64), "abc");
  assert.equal(sanitizeDisplayText("Agent-Q Firmware", 64), "Agent-Q Firmware");
  assert.equal(sanitizeDisplayText(BEL + DEL + "ok", 64), "ok");
  assert.equal(sanitizeDisplayText(NUL + "x", 64), "x");
  assert.equal(sanitizeDisplayText(HIGH + "ok", 64), "ok");
  assert.equal(sanitizeDisplayText("x".repeat(100), 10).length, 10);
  assert.equal(sanitizeDisplayText(123, 64), "");
  assert.equal(sanitizeDisplayText(null, 64), "");
});

test("sanitizePortHint sanitizes as display text within the port-hint bound", () => {
  assert.equal(sanitizePortHint("/dev/cu.usbmodem1"), "/dev/cu.usbmodem1");
  assert.equal(sanitizePortHint("COM3"), "COM3");
  assert.equal(sanitizePortHint("/dev/cu." + BEL + "x"), "/dev/cu.x");
  assert.equal(sanitizePortHint("x".repeat(MAX_PORT_HINT_LENGTH + 10)).length, MAX_PORT_HINT_LENGTH);
});
