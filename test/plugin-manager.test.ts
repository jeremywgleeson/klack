import assert from "node:assert/strict";
import test from "node:test";

import { normalizeSlackColor } from "../plugins/lib/plugin-manager";

test("wraps Slack's raw RGB channel variables in a valid color function", () => {
  assert.equal(normalizeSlackColor("29, 28, 29"), "rgb(29, 28, 29)");
  assert.equal(normalizeSlackColor(" 255,255,255 "), "rgb(255,255,255)");
  assert.equal(normalizeSlackColor("12.5%, 0%, 100%"), "rgb(12.5%, 0%, 100%)");
});

test("preserves complete colors supplied by Klack and custom themes", () => {
  for (const color of [
    "#1a1d21",
    "rgb(29 28 29 / 62%)",
    "rgba(29, 28, 29, 0.62)",
    "oklch(42% 0.12 315)",
    "color-mix(in srgb, black 60%, transparent)",
    "var(--custom-dialog-background)",
    "transparent",
  ]) {
    assert.equal(normalizeSlackColor(`  ${color}  `), color);
  }
  assert.equal(normalizeSlackColor(""), undefined);
  assert.equal(normalizeSlackColor("29, 28"), "29, 28");
});
