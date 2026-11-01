#!/usr/bin/env node
import { advisoriesUsage, runAdvisoriesCommand } from "./cli/advisories-v1.js";
import {
  exitCodes,
  findingsUsage,
  readUsage,
  runFindingsCommand,
  runReadCommand,
  runScanCommandV1,
  scanUsage,
} from "./cli/commands-v1.js";
import { runSignCommand, runVerifyCommand, signUsage, verifyUsage } from "./cli/sign-verify-v1.js";
import { commandsUsage } from "./cli/usage.js";

const usage = commandsUsage([
  scanUsage,
  advisoriesUsage,
  readUsage,
  findingsUsage,
  verifyUsage,
  signUsage,
]);

const io = {
  stdout: (text: string) => void process.stdout.write(text),
  stderr: (text: string) => void process.stderr.write(text),
};

/**
 * Runs a cancellable command. The first SIGINT or SIGTERM cancels the work so the command can
 * still report what finished (exit 130); a second one stops immediately. The handlers exist only
 * while the command runs.
 */
async function cancellable(
  run: (cancellation: AbortSignal) => Promise<number>,
  what: string,
): Promise<void> {
  const cancellation = new AbortController();
  let signals = 0;
  const onSignal = (signal: NodeJS.Signals) => {
    signals += 1;
    if (signals > 1) process.exit(exitCodes.cancelled);
    process.stderr.write(
      `aih-scan: ${signal} received; cancelling the ${what} (send it again to stop immediately)\n`,
    );
    cancellation.abort();
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  try {
    process.exitCode = await run(cancellation.signal);
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  switch (command) {
    case "scan":
      return cancellable(
        (cancellation) => runScanCommandV1(args, { ...io, cancellation }),
        "assessment",
      );
    case "advisories":
      return cancellable(
        (cancellation) => runAdvisoriesCommand(args, { ...io, cancellation }),
        "advisory check",
      );
    case "read":
      process.exitCode = runReadCommand(args, io);
      return;
    case "findings":
      process.exitCode = await runFindingsCommand(args, io);
      return;
    case "verify":
      process.exitCode = await runVerifyCommand(args, io);
      return;
    case "sign":
      process.exitCode = await runSignCommand(args, io);
      return;
    case "--help":
    case "-h":
      process.stdout.write(usage);
      return;
    default:
      process.stderr.write(`aih-scan: unknown command\n${usage}`);
      process.exitCode = exitCodes.input;
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "invalid input"}\n`);
  process.exitCode = exitCodes.input;
});
