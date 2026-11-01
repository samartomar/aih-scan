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
      provider: "v8",
      include: ["src/**/*.ts"],
      // The bin dispatcher runs only as the installed subprocess in
      // tests/package-install.test.ts; V8 coverage from that child process is not merged
      // into Vitest's in-process report. Every command it dispatches is covered in-process.
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
