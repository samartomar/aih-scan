// A three-level node -> node -> node process tree for the real containment tests.
//
// usage: node tree.mjs <depth> <marker> <mode> <attach|detach>
//
// Every process carries <marker> in its command line so a test can find survivors.
// With "detach" each level starts its child detached: on Windows that child is outside
// Node's own per-process job object, and on POSIX it leads a new session and process
// group, so only an outer containment (a Job Object, or Scan's residual sweep) ends it.
// With "attach" children stay in their parent's process group.
//
// modes:
//   wait    every level waits for its child; the leaf sleeps for 60 s
//   orphan  the leader starts its child and exits after 500 ms; the rest sleep
//   quick   the leaf writes a byte-exact probe to stdout; every level exits 0
//   echo    write the arguments after the script path as JSON and exit 0
import { spawn } from "node:child_process";

const [depthText, marker, mode, placement] = process.argv.slice(2);
const depth = Number(depthText);
if (mode === "echo") {
  process.stdout.write(JSON.stringify(process.argv.slice(2)));
  process.exit(0);
}
if (depth <= 1) {
  if (mode === "quick") {
    process.stdout.write(Buffer.from([0x70, 0x72, 0x6f, 0x62, 0x65, 0x00, 0xff, 0xe2, 0x9c, 0x93, 0x0a]));
    process.exit(0);
  }
  setTimeout(() => process.exit(0), 60_000);
} else {
  const orphan = mode === "orphan";
  const child = spawn(
    process.execPath,
    [import.meta.filename, String(depth - 1), marker, orphan ? "wait" : mode, placement],
    {
      stdio: orphan ? "ignore" : "inherit",
      windowsHide: true,
      detached: placement === "detach",
    },
  );
  if (orphan) {
    child.unref();
    setTimeout(() => process.exit(0), 500);
  } else child.on("exit", (code) => process.exit(code ?? 1));
}
