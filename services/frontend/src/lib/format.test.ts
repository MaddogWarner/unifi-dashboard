import { describe, expect, it } from "vitest";

import { formatTimestamp, relativeTime } from "./format";

const now = Date.parse("2026-11-15T12:00:00Z");
const ago = (ms: number) => new Date(now - ms).toISOString();

describe("relativeTime", () => {
  it("returns null for missing values", () => {
    expect(relativeTime(null, now)).toBeNull();
  });

  it.each([
    [59_000, "just now"],
    [60_000, "1 min ago"],
    [59 * 60_000, "59 min ago"],
    [60 * 60_000, "1 h ago"],
    [23 * 3_600_000, "23 h ago"],
    [24 * 3_600_000, "1 d ago"],
    [6 * 86_400_000, "6 d ago"]
  ])("formats %i ms as %s", (elapsed, expected) => {
    expect(relativeTime(ago(elapsed), now)).toBe(expected);
  });

  it("falls back to the absolute format after a week", () => {
    const old = ago(7 * 86_400_000);
    expect(relativeTime(old, now)).toBe(formatTimestamp(old));
  });

  it("clamps future timestamps to just now", () => {
    expect(relativeTime(new Date(now + 5 * 60_000).toISOString(), now)).toBe("just now");
  });
});
