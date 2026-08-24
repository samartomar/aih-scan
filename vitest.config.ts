import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // The CLI is exercised as the packed subprocess boundary in
      // tests/package-install-v2.test.ts; V8 coverage from that child process
      // is not merged into Vitest's in-process report.
      exclude: ["src/cli.ts"],
      reporter: ["text"],
      thresholds: {
        statements: 80,
        branches: 80,
        functions: 80,
        lines: 80,
      },
    },
  },
});
