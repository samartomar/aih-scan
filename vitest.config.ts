import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Keep scans hermetic: an analyzer installed on this machine never runs unless a test
    // selects it explicitly (the real-analyzer tests read AIH_SCAN_TEST_SKILLSPECTOR and
    // AIH_SCAN_TEST_SKILL_SCANNER and pass those paths through the scan's internal env).
    env: { AIH_SCAN_SKILLSPECTOR: "none", AIH_SCAN_SKILL_SCANNER: "none" },
    coverage: {
      provider: "custom",
      customProviderModule: "./tools/packed-coverage-provider.mjs",
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
