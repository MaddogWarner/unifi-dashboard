import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

export const RANGES = ["1h", "24h", "7d", "all"] as const;
export const ACTIONS = ["", "drop", "accept", "reject"] as const;

export type LogFilters = {
  src_ip: string;
  dst_ip: string;
  rule_name: string;
  action: (typeof ACTIONS)[number];
  range: (typeof RANGES)[number];
  page: number;
};

export const DEFAULT_FILTERS: LogFilters = {
  src_ip: "",
  dst_ip: "",
  rule_name: "",
  action: "",
  range: "24h",
  page: 1
};

const TEXT_KEYS = ["src_ip", "dst_ip", "rule_name"] as const;
const FILTER_KEYS = [...TEXT_KEYS, "action", "range", "page"] as const;

export function parseFilters(params: URLSearchParams): LogFilters {
  const action = params.get("action") ?? "";
  const range = params.get("range") ?? DEFAULT_FILTERS.range;
  const page = Number.parseInt(params.get("page") ?? "", 10);
  return {
    src_ip: params.get("src_ip") ?? "",
    dst_ip: params.get("dst_ip") ?? "",
    rule_name: params.get("rule_name") ?? "",
    action: (ACTIONS as readonly string[]).includes(action) ? (action as LogFilters["action"]) : "",
    range: (RANGES as readonly string[]).includes(range) ? (range as LogFilters["range"]) : DEFAULT_FILTERS.range,
    page: Number.isFinite(page) && page >= 1 ? page : 1
  };
}

// Writes only non-default values so URLs stay short; unrelated params (e.g. `tab`) are preserved.
// Changing any filter other than `page` resets paging.
export function applyFilters(params: URLSearchParams, patch: Partial<LogFilters>): URLSearchParams {
  const next = new URLSearchParams(params);
  const merged: LogFilters = {
    ...parseFilters(params),
    ...patch,
    page: patch.page ?? (Object.keys(patch).length > 0 ? 1 : parseFilters(params).page)
  };
  for (const key of FILTER_KEYS) next.delete(key);
  for (const key of FILTER_KEYS) {
    const value = merged[key];
    if (value !== DEFAULT_FILTERS[key]) next.set(key, String(value));
  }
  return next;
}

export function activeFilters(filters: LogFilters) {
  return [...TEXT_KEYS, "action", "range"].flatMap((key) => {
    const value = filters[key as keyof LogFilters];
    return value !== DEFAULT_FILTERS[key as keyof LogFilters] ? [{ key: key as keyof LogFilters, value: String(value) }] : [];
  });
}

export function fromTimestamp(range: LogFilters["range"], now = Date.now()) {
  const hours = { "1h": 1, "24h": 24, "7d": 168, all: 0 }[range];
  return hours ? new Date(now - hours * 3_600_000).toISOString() : undefined;
}

export function useLogFilters() {
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => parseFilters(searchParams), [searchParams]);
  const update = useCallback(
    (patch: Partial<LogFilters>) => setSearchParams((current) => applyFilters(current, patch)),
    [setSearchParams]
  );
  const clear = useCallback(
    () =>
      setSearchParams((current) => {
        const next = new URLSearchParams(current);
        for (const key of FILTER_KEYS) next.delete(key);
        return next;
      }),
    [setSearchParams]
  );
  return { filters, update, clear };
}
