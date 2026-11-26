import { randomBytes } from "node:crypto";
import { createServer } from "node:net";

const frameBytes = 2 * 1024 * 1024;
// Nearby prepared workers reach the same detector independently.
const gatherMs = 750;
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const frame = (value) => `${JSON.stringify(value)}\n`;

/** A prepared run owns one rendezvous. Only its children receive the capability. */
export async function startPreparedBatching(signal) {
  signal.throwIfAborted();
  const token = randomBytes(32).toString("hex");
  const pending = new Map();
  const sockets = new Set();
  let closePromise;

  function finish(entry, reply) {
    if (entry.finished) return;
    entry.finished = true;
    entry.socket.end(frame(reply));
  }

  function flush(key) {
    const queue = pending.get(key);
    if (!queue) return;
    pending.delete(key);
    clearTimeout(queue.timer);
    const entries = queue.entries.filter((entry) => !entry.socket.destroyed);
    while (entries.length) {
      const group = [];
      while (entries.length) {
        const candidate = [...group, entries[0]];
        const request = frame({ dispatch: candidate.flatMap((entry) => entry.tasks) });
        if (Buffer.byteLength(request) > frameBytes) break;
        group.push(entries.shift());
      }
      if (group.length < 2) {
        finish(group[0] ?? entries.shift(), { native: true });
        continue;
      }
      const [leader] = group;
      leader.group = group;
      leader.socket.write(frame({ dispatch: group.flatMap((entry) => entry.tasks) }));
    }
  }

  const server = createServer((socket) => {
    sockets.add(socket);
    let buffer = Buffer.alloc(0);
    const entry = { socket };
    socket.on("error", () => socket.destroy());
    socket.on("close", () => {
      sockets.delete(socket);
      if (entry.group && !entry.finished)
        for (const member of entry.group) finish(member, { failed: true });
    });
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > frameBytes) { socket.destroy(); return; }
      const newline = buffer.indexOf(10);
      if (newline < 0) return;
      if (newline !== buffer.length - 1) { socket.destroy(); return; }
      let message;
      try { message = JSON.parse(buffer.toString("utf8")); }
      catch { socket.destroy(); return; }
      buffer = Buffer.alloc(0);
      if (entry.group) {
        const { results } = object(message) ? message : {};
        const submitted = entry.group.reduce((count, member) => count + member.tasks.length, 0);
        if (results === null) {
          for (const member of entry.group) finish(member, { native: true });
          return;
        }
        if (!Array.isArray(results) || results.length !== submitted ||
          results.some((result) => result !== null && !object(result))) {
          socket.destroy();
          return;
        }
        let index = 0;
        for (const member of entry.group) {
          const end = index + member.tasks.length;
          finish(member, { results: results.slice(index, end) });
          index = end;
        }
        return;
      }
      if (entry.tasks || !object(message) || message.token !== token ||
        typeof message.group !== "string" || !/^[0-9a-f]{64}$/u.test(message.group) ||
        !Array.isArray(message.tasks) || !message.tasks.length ||
        message.tasks.some((task) => !object(task) || typeof task.prompt !== "string" ||
          !Number.isSafeInteger(task.output) || task.output < 1)) {
        socket.destroy();
        return;
      }
      entry.tasks = message.tasks.map(({ prompt, output }) => ({ prompt, output }));
      const key = message.group;
      if (!pending.has(key))
        pending.set(key, { entries: [], timer: setTimeout(() => flush(key), gatherMs) });
      const queue = pending.get(key);
      queue.entries.push(entry);
    });
  });

  function close() {
    if (!closePromise) {
      signal.removeEventListener("abort", close);
      for (const queue of pending.values()) clearTimeout(queue.timer);
      pending.clear();
      for (const socket of sockets) socket.destroy();
      closePromise = new Promise((resolve) => server.close(resolve));
    }
    return closePromise;
  }

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  server.on("error", close);
  signal.addEventListener("abort", close, { once: true });
  const { port } = server.address();
  if (signal.aborted) {
    await close();
    signal.throwIfAborted();
  }
  return { port, token, close };
}
