import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiUrl = env.VITE_API_URL || "http://localhost:8000";

  return {
    plugins: [react(), tailwindcss()],
    test: {
      environment: "jsdom",
      environmentOptions: { jsdom: { url: "http://localhost/" } },
      setupFiles: ["./src/test-setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"]
    },
    server: {
      port: 5173,
      proxy: {
        "/api": apiUrl
      }
    }
  };
});
