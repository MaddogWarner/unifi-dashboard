import { describe, expect, it } from "vitest";

import { activeFilters, applyFilters, DEFAULT_FILTERS, fromTimestamp, parseFilters } from "./logFilters";

const params = (query: string) => new URLSearchParams(query);

describe("parseFilters", () => {
  it("returns defaults for an empty query", () => {
    expect(parseFilters(params(""))).toEqual(DEFAULT_FILTERS);
  });

  it("reads valid values", () => {
    expect(parseFilters(params("src_ip=1.2.3.4&action=drop&range=7d&page=3&rule_name=Block"))).toEqual({
      src_ip: "1.2.3.4",
      dst_ip: "",
      rule_name: "Block",
      action: "drop",
      range: "7d",
      page: 3
    });
  });

  it("falls back for invalid action, range and page", () => {
    const parsed = parseFilters(params("action=nuke&range=forever&page=-2"));
    expect(parsed.action).toBe("");
    expect(parsed.range).toBe("24h");
    expect(parsed.page).toBe(1);
    expect(parseFilters(params("page=abc")).page).toBe(1);
  });
});

describe("applyFilters", () => {
  it("round-trips through parse", () => {
    const next = applyFilters(params(""), { src_ip: "10.0.0.1", action: "reject", range: "all" });
    expect(parseFilters(next)).toMatchObject({ src_ip: "10.0.0.1", action: "reject", range: "all", page: 1 });
  });

  it("omits defaults and keeps unrelated params", () => {
    const next = applyFilters(params("tab=logs&src_ip=1.1.1.1&range=7d"), { src_ip: "", range: "24h" });
    expect(next.toString()).toBe("tab=logs");
  });

  it("resets paging when a filter changes but not when only page changes", () => {
    expect(applyFilters(params("page=4"), { action: "drop" }).get("page")).toBeNull();
    expect(applyFilters(params("src_ip=1.1.1.1"), { page: 3 }).get("page")).toBe("3");
  });
});

describe("activeFilters and fromTimestamp", () => {
  it("lists only non-default filters", () => {
    expect(activeFilters({ ...DEFAULT_FILTERS, dst_ip: "9.9.9.9", range: "1h" })).toEqual([
      { key: "dst_ip", value: "9.9.9.9" },
      { key: "range", value: "1h" }
    ]);
  });

  it("computes the lower bound for a range", () => {
    const now = Date.parse("2026-11-15T12:00:00Z");
    expect(fromTimestamp("1h", now)).toBe("2026-11-15T11:00:00.000Z");
    expect(fromTimestamp("all", now)).toBeUndefined();
  });
});
