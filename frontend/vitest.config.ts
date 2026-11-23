import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Configuración separada de vite.config.ts: los tests no necesitan Tailwind ni el proxy.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
  },
});
