#pragma once

#include <cstdint>

#include "lvgl.h"

// Agent-Q device UI theme — token table (Material-Design role names, NES light palette).
//
// Single source of truth for color, shape, and typography across every panel and
// modal. Drawing code references these semantic *roles* instead of raw literals,
// so the whole device shares one palette and re-theming is a single-file edit.
//
// This prevents per-modal drift: with this table there is one definition per
// role, so a modal cannot diverge without editing the shared token.
//
// Color values are 0xRRGGBB; wrap a role with lv_color_hex(role) at the call site.
//
// ── Active theme: NES (Famicom) light palette ────────────────────────────────
// Light background, saturated mid-tone accents, black ink + black outlines.
//
// Panel contrast constraint: the CoreS3 panel is a 2.0" IPS LCD (ILI9342C) with
// a weak black level — its backlight bleeds through dark-but-non-black pixels,
// so a dark theme renders washed/hazy (e.g. a #1E1E24 navy surface shows as
// milky light-blue), and the backlight curve (reg 20..28) keeps even "low"
// brightness fairly bright.
// Verified empirically: a magenta fill renders vivid and pure #000000 renders true
// black, but mid-dark values lift. A light surface plays to the panel's strength, so
// the wash disappears. Re-theming is a single edit here — but keep backgrounds light.

namespace agent_q {
namespace theme {

// ── Color roles ──────────────────────────────────────────────────────────────
// Each role is mapped to the active (NES light) palette and annotated with its use.

// Primary — affirmative actions (Confirm / Sign / Accept) + keypad/input accents.
constexpr uint32_t kPrimary = 0x00A2E8;               // NES blue
constexpr uint32_t kOnPrimary = 0xFFFFFF;             // label on primary/error buttons (white)
constexpr uint32_t kPrimaryContainer = 0xCFE8FC;      // active/selected input-slot fill (light blue)

// Secondary — neutral / dismissive actions (Cancel / Close / Back).
constexpr uint32_t kSecondary = 0x9A8F7E;             // warm neutral gray (white label)

// Error — destructive / rejecting actions (Reject / Erase / Reset) and error copy.
constexpr uint32_t kError = 0xE52521;                 // NES red
constexpr uint32_t kOnError = 0xFFFFFF;               // label on error
constexpr uint32_t kErrorContainer = 0xFDECEC;        // error/danger panel background
constexpr uint32_t kOnErrorContainer = 0xA1100E;      // text on error container
constexpr uint32_t kOnErrorContainerStrong = 0x6E0A08;// strongest error copy

// Warning — cautionary, non-fatal advisories.
constexpr uint32_t kWarning = 0xE58E26;               // amber / orange copy

// Surface — panels / backgrounds and the text drawn on them.
constexpr uint32_t kSurface = 0xFFFFFF;               // modal panel + input cell background (white)
constexpr uint32_t kOnSurface = 0x000000;             // body + title text (black ink)
constexpr uint32_t kOnSurfaceVariant = 0x555555;      // secondary text / row labels

// Outline — borders, dividers, inactive tracks.
constexpr uint32_t kOutline = 0x000000;               // input cell border (NES black outline)
constexpr uint32_t kOutlineVariant = 0xD8D0C0;        // timer-bar track / disabled track

// State — interaction + disabled.
constexpr uint32_t kPressed = 0x00A2E8;               // pressed/active accent (= primary blue)
constexpr uint32_t kDisabledOnSurface = 0xB0A89A;     // disabled control text
constexpr uint32_t kDisabledOnAction = 0xC0B8AA;      // disabled action-button text

// ── Shape (corner radius) ────────────────────────────────────────────────────
constexpr int kRadiusSmall = 6;   // compact controls (PIN / keypad cells)
constexpr int kRadiusMedium = 7;  // action buttons

// ── Typography ───────────────────────────────────────────────────────────────
// The device currently ships a single bundled size; these roles give call sites
// a semantic name and a single place to add a broader type scale.
inline const lv_font_t* font_title() { return &lv_font_montserrat_14; }
inline const lv_font_t* font_body() { return &lv_font_montserrat_14; }
inline const lv_font_t* font_label() { return &lv_font_montserrat_14; }

}  // namespace theme
}  // namespace agent_q
