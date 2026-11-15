import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const log = (id: number, src: string, rule: string, action = "drop") => ({
  id,
  timestamp: new Date(Date.now() - id * 60_000).toISOString(),
  rule_name: rule,
  action,
  src_ip: src,
  dst_ip: "192.168.1.10",
  src_port: 40000 + id,
  dst_port: 443,
  protocol: "TCP",
  interface: "eth4",
  direction: "IN",
  matched_policy_id: 1,
  raw_line: `raw line ${id}`
});

const allLogs = [log(1, "203.0.113.7", "Block-WAN"), log(2, "198.51.100.9", "Block-Guest"), log(3, "203.0.113.7", "Block-WAN")];

const summary = {
  total: 3,
  blocked: 3,
  top_sources: [
    { ip: "203.0.113.7", count: 2 },
    { ip: "198.51.100.9", count: 1 }
  ],
  top_ports: [{ port: 443, protocol: "TCP", count: 3 }],
  top_rules: [
    { rule_name: "Block-WAN", count: 2 },
    { rule_name: "Block-Guest", count: 1 }
  ]
};

let logRequests: URL[] = [];

async function mockApi(page: Page) {
  logRequests = [];
  await page.addInitScript(() => localStorage.setItem("auth_token", "test-token"));
  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace("/api/v1", "");
    if (path === "/auth/setup-status") return route.fulfill({ json: { configured: true } });
    if (path === "/firewall/logs/summary") return route.fulfill({ json: summary });
    if (path === "/firewall/logs") {
      logRequests.push(url);
      const src = url.searchParams.get("src_ip");
      const rule = url.searchParams.get("rule_name");
      return route.fulfill({
        json: allLogs.filter((l) => (!src || l.src_ip === src) && (!rule || l.rule_name === rule))
      });
    }
    return route.fulfill({ json: [] });
  });
}

function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

test("filters are restored from the URL, including after reload", async ({ page }) => {
  const errors = collectErrors(page);
  await mockApi(page);
  await page.goto("/firewall?tab=logs&src_ip=203.0.113.7&action=drop&range=7d");

  await expect(page.getByLabel("Source IP")).toHaveValue("203.0.113.7");
  await expect(page.getByRole("combobox", { name: /^Action/ })).toHaveValue("drop");
  await expect(page.getByRole("combobox", { name: /^Time range/ })).toHaveValue("7d");
  await expect(page.getByRole("button", { name: "Remove filter src_ip 203.0.113.7" })).toBeVisible();
  expect(logRequests.at(-1)?.searchParams.get("src_ip")).toBe("203.0.113.7");

  await page.reload();
  await expect(page.getByLabel("Source IP")).toHaveValue("203.0.113.7");
  expect(errors).toEqual([]);
});

test("clicking a source IP pivots, and the chip can be removed", async ({ page }) => {
  await mockApi(page);
  await page.goto("/firewall?tab=logs");

  const pivot = page.getByRole("button", { name: "198.51.100.9" }).first();
  await pivot.click();
  await expect(page).toHaveURL(/src_ip=198\.51\.100\.9/);
  await expect(page).toHaveURL(/tab=logs/);
  await expect(page.getByRole("button", { name: "Remove filter src_ip 198.51.100.9" })).toBeVisible();

  await page.getByRole("button", { name: "Remove filter src_ip 198.51.100.9" }).click();
  await expect(page).not.toHaveURL(/src_ip/);
});

test("summary entries apply filters", async ({ page }) => {
  await mockApi(page);
  await page.goto("/firewall?tab=logs");
  await page.getByRole("button", { name: "Block-Guest" }).first().click();
  await expect(page).toHaveURL(/rule_name=Block-Guest/);
});

test("details drawer opens, closes on Escape and restores focus", async ({ page }, testInfo) => {
  const isMobile = testInfo.project.name === "mobile";
  const errors = collectErrors(page);
  await mockApi(page);
  await page.goto("/firewall?tab=logs");

  const opener = isMobile
    ? page.getByRole("button", { name: "Details" }).first()
    : page.getByRole("row", { name: /Open details for event/ }).first();
  await opener.focus();
  await opener.press("Enter");

  const dialog = page.getByRole("dialog", { name: "Firewall event" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("raw line 1")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();
  expect(errors).toEqual([]);
});

test("mobile layout has no horizontal overflow", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile", "mobile only");
  await mockApi(page);
  await page.goto("/firewall?tab=logs");
  await expect(page.getByRole("button", { name: "Details" }).first()).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
});
