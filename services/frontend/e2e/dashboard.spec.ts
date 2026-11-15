import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

const item = (severity: string, title: string) => ({
  severity,
  category: "assessment",
  title,
  detail: `${title} detail`,
  link: "/assessment",
  timestamp: minutesAgo(5)
});

const check = (id: string, status: string) => ({
  check_id: id,
  label: `Check ${id}`,
  status,
  detail: "d",
  recommendation: "r",
  evidence: []
});

let attentionRequests = 0;

async function mockApi(page: Page) {
  attentionRequests = 0;
  await page.addInitScript(() => localStorage.setItem("auth_token", "test-token"));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1", "");
    const fixtures: Record<string, unknown> = {
      "/auth/setup-status": { configured: true },
      "/dashboard/attention": () => {
        attentionRequests += 1;
        return {
          generated_at: minutesAgo(3),
          status: {
            assessment_score: 72,
            unifi_reachable: true,
            last_policy_sync: minutesAgo(10),
            last_syslog_event: minutesAgo(2),
            threat_events_24h: 1
          },
          items: [item("info", "Info one"), item("critical", "Critical one"), item("warning", "Warning one")]
        };
      },
      "/assessment/": { score: 72, pass_count: 2, warn_count: 0, fail_count: 1, checks: [check("a", "pass"), check("b", "fail"), check("c", "pass")] },
      "/assessment/history": [
        { created_at: minutesAgo(3000), score: 60, pass_count: 1, warn_count: 0, fail_count: 2, checks: [] },
        { created_at: minutesAgo(1000), score: 72, pass_count: 2, warn_count: 0, fail_count: 1, checks: [] }
      ]
    };
    const fixture = fixtures[path] ?? [];
    return route.fulfill({ json: typeof fixture === "function" ? fixture() : fixture });
  });
}

test("dashboard groups attention items by severity and refreshes", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");

  const groups = page.locator("section[aria-label$=' items']");
  await expect(groups).toHaveCount(3);
  await expect(groups.nth(0)).toHaveAttribute("aria-label", "Critical items");
  await expect(groups.nth(1)).toHaveAttribute("aria-label", "Warning items");
  await expect(groups.nth(2)).toHaveAttribute("aria-label", "Info items");
  await expect(page.getByText("10 min ago")).toBeVisible();
  await expect(page.getByText("Updated 3 min ago")).toBeVisible();

  const before = attentionRequests;
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect.poll(() => attentionRequests).toBeGreaterThan(before);
});

test("assessment shows the score ring and collapses passing checks", async ({ page }) => {
  await mockApi(page);
  await page.goto("/assessment");

  await expect(page.getByRole("img", { name: "Security score 72 out of 100" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Check b" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Check a" })).toBeHidden();

  await page.getByText("2 passing checks").click();
  await expect(page.getByRole("heading", { name: "Check a" })).toBeVisible();
});
