import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

const user = { id: "1", email: "admin@example.test", is_active: true, is_superuser: true, theme: "light" };

const fixtures: Record<string, unknown> = {
  "/auth/setup-status": { configured: true },
  "/auth/me": user,
  "/dashboard/attention": {
    status: {
      assessment_score: 72,
      unifi_reachable: true,
      last_policy_sync: null,
      last_syslog_event: null,
      threat_events_24h: 0
    },
    items: [
      {
        category: "assessment",
        severity: "warning",
        title: "Example finding",
        detail: "Fixture item",
        link: "/assessment",
        timestamp: null
      }
    ]
  },
  "/assessment/": { score: 72, pass_count: 7, warn_count: 2, fail_count: 1, checks: [] },
  "/settings/": {}
};

async function mockApi(page: Page) {
  await page.route("**/api/v1/**", (route: Route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1", "");
    const body = fixtures[path] ?? fixtures[path.replace(/\/?$/, "/")] ?? [];
    return route.fulfill({ json: body });
  });
}

const routes = [
  { path: "/", heading: "Dashboard" },
  { path: "/firewall", heading: "Firewall" },
  { path: "/threats", heading: "Threats" },
  { path: "/assessment", heading: "Security Assessment" },
  { path: "/scanner", heading: "Scanner" },
  { path: "/settings", heading: "Settings" }
];

for (const { path, heading } of routes) {
  test(`${heading} renders without console errors`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    await page.addInitScript(() => localStorage.setItem("auth_token", "test-token"));
    await mockApi(page);
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    expect(errors).toEqual([]);
  });
}
