import { describe, expect, it } from "vitest";

import type { AttentionItem } from "../lib/api";
import { groupBySeverity, olderThan24h, scoreTone } from "./Dashboard";

describe("scoreTone", () => {
  it.each([
    [null, "neutral"],
    [100, "good"],
    [80, "good"],
    [79, "warn"],
    [50, "warn"],
    [49, "bad"],
    [0, "bad"]
  ])("maps %s to %s", (score, tone) => {
    expect(scoreTone(score)).toBe(tone);
  });
});

describe("olderThan24h", () => {
  it("treats missing timestamps as not stale", () => {
    expect(olderThan24h(null)).toBe(false);
  });

  it("flags timestamps older than a day only", () => {
    const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
    expect(olderThan24h(hoursAgo(25))).toBe(true);
    expect(olderThan24h(hoursAgo(23))).toBe(false);
  });
});

describe("groupBySeverity", () => {
  const item = (severity: AttentionItem["severity"], title: string): AttentionItem => ({
    severity,
    category: "assessment",
    title,
    detail: "",
    link: "/",
    timestamp: null
  });

  it("orders groups critical, warning, info and omits empty ones", () => {
    const groups = groupBySeverity([item("info", "c"), item("critical", "a"), item("info", "d")]);
    expect(groups.map((g) => [g.severity, g.items.length])).toEqual([
      ["critical", 1],
      ["info", 2]
    ]);
  });

  it("returns no groups for no items", () => {
    expect(groupBySeverity([])).toEqual([]);
  });
});
