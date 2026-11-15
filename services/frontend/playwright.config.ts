import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  webServer: {
    command: "npm run dev -- --port 5173",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI
  },
  use: {
    baseURL: "http://localhost:5173",
    // Lets a machine with an older cached Chromium run without downloading a new browser.
    launchOptions: { executablePath: process.env.PW_CHROMIUM_PATH || undefined }
  },
  projects: [
    { name: "desktop", use: { viewport: { width: 1280, height: 800 } } },
    { name: "mobile", use: { viewport: { width: 390, height: 844 } } }
  ]
});
