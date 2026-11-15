import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { apiLogin, del, get, getFirewallLogs, post } from "./api";

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), { status: 200, ...init });
}

describe("api client", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    localStorage.clear();
  });

  afterEach(() => {
    fetchMock.mockReset();
    vi.unstubAllGlobals();
  });

  it("sends the bearer token when one is stored", async () => {
    localStorage.setItem("auth_token", "abc");
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));
    await get("/health");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/health", { headers: { Authorization: "Bearer abc" } });
  });

  it("omits Authorization when logged out", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({})));
    await get("/health");
    expect(fetchMock.mock.calls[0][1].headers).toEqual({});
  });

  it("clears the token and rejects on 401", async () => {
    localStorage.setItem("auth_token", "abc");
    fetchMock.mockImplementation(() => Promise.resolve(new Response(null, { status: 401 })));
    await expect(get("/x")).rejects.toThrow("Session expired");
    expect(localStorage.getItem("auth_token")).toBeNull();
  });

  it("surfaces a string detail from error payloads", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ detail: "Nope" }, { status: 400 })));
    await expect(get("/x")).rejects.toThrow("Nope");
  });

  it("falls back to the status line when the error body is not usable", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response("<html>", { status: 502, statusText: "Bad Gateway" })));
    await expect(get("/x")).rejects.toThrow("502 Bad Gateway");
  });

  it("ignores non-string validation details", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ detail: [{ msg: "bad" }] }, { status: 422, statusText: "Unprocessable" })));
    await expect(get("/x")).rejects.toThrow("422 Unprocessable");
  });

  it("returns undefined for 204 responses", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response(null, { status: 204 })));
    await expect(del("/x")).resolves.toBeUndefined();
  });

  it("posts JSON with a content type only when a body is given", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({})));
    await post("/x", { a: 1 });
    await post("/y");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: '{"a":1}',
      headers: { "Content-Type": "application/json" }
    });
    expect(fetchMock.mock.calls[1][1].headers).toEqual({});
    expect(fetchMock.mock.calls[1][1].body).toBeUndefined();
  });

  it("builds log queries without empty params", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse([])));
    await getFirewallLogs({ limit: 50, src_ip: "", rule_name: "WAN" } as never);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/firewall/logs?limit=50&rule_name=WAN");
  });

  it("returns the access token on login and rejects bad credentials", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ access_token: "tok" }));
    await expect(apiLogin("a@b.test", "pw")).resolves.toBe("tok");
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 400 }));
    await expect(apiLogin("a@b.test", "bad")).rejects.toThrow("Invalid credentials");
  });
});
