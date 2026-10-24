#!/usr/bin/env node
// aih-extensions commit gate: a git commit-msg hook, installed by /install-commit-gate.
// It reads what git is actually about to commit (the index, or the temporary
// index git builds for `git commit -- <paths>`) and blocks:
//   always  - conflict markers, and [DEBUG-xxxx] tags left over from diagnosing-bugs
//   floor   - new checker suppressions, skipped tests, deleted test files, a net
//             loss of assertions, unimplemented stubs; unless the commit message
//             carries [floor-ok: <reason>]. Merge commits skip the floor, since
//             the incoming branch's lines are not this change.
// Paths listed in .floorignore are skipped. People can still bypass with --no-verify;
// an enabled aih-extensions git-guard can block that agent command.
// Hook line: node .githooks/commit-gate.mjs "$1"     Check itself: node commit-gate.mjs --self-test
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const VERSION = '0.2.0';

const CODE = /\.(c|cc|cpp|cs|cjs|cts|dart|ex|exs|go|h|hpp|java|js|jsx|kt|kts|lua|mjs|mts|php|py|rb|rs|scala|sh|swift|ts|tsx|vue|svelte)$/i;
const TEST = /(^|\/)(__tests__|tests?|spec)\/|\.(test|spec)\.[a-z]+$|_test\.[a-z]+$|(^|\/)test_[^/]*$/i;
const CONFLICT = /^(<{7}|>{7})( |$)/;
const DEBUG_TAG = /\[DEBUG-[A-Za-z0-9]{2,8}\]/;
const SUPPRESSION = /@ts-ignore|@ts-nocheck|eslint-disable|biome-ignore|#\s*noqa|#\s*type:\s*ignore|istanbul ignore|nosemgrep|gitleaks:allow|Stryker disable|#\s*pragma: no cover|\/\/\s*nolint/;
const STUB = /throw new \w*Error\(\s*['"`][^'"`]*not implemented|\braise NotImplementedError\b|\bunimplemented!\(|\btodo!\(|panic\(\s*"not implemented|catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}/i;
const SKIP = /\.(skip|todo)\s*\(|\bx(it|describe|test)\s*\(|@pytest\.mark\.skip|\bt\.Skip\(|@Disabled\b|@Ignore\b/;
// An assertion call, not the word "should" in a test title.
const ASSERTION = /\bexpect\s*\(|\bassert\w*\s*[.(]|\.should\b|\bt\.(is|ok|notOk|true|false|equal|deepEqual|throws)\s*\(|\bself\.assert\w+\(/;

// gitignore-ish: `dir/` matches below dir at the root, `*.ext` matches anywhere,
// a pattern containing `/` is anchored at the repo root.
export function loadIgnore(root, extra = []) {
  const file = path.join(root, '.floorignore');
  const lines = [...extra, ...(fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split(/\r?\n/) : [])];
  const res = lines.map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((glob) => {
    const isDir = glob.endsWith('/');
    const pattern = glob.replace(/^\//, '').replace(/\/$/, '');
    const body = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*\//g, '\u0001').replace(/\*\*/g, '\u0002')
      .replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')
      .replace(/\u0001/g, '(?:.*/)?').replace(/\u0002/g, '.*');
    return new RegExp(pattern.includes('/') || isDir ? `^${body}${isDir ? '/.*' : ''}$` : `(^|/)${body}$`);
  });
  return (f) => res.some((re) => re.test(f));
}

const unquote = (p) => { if (p.startsWith('"') && p.endsWith('"')) { try { return JSON.parse(p); } catch { return p.slice(1, -1); } } return p; };
// Header path after `--- ` / `+++ `: git appends a tab to names containing spaces, and C-quotes odd ones.
const headerPath = (s, prefix) => { const p = unquote(s.replace(/\t.*$/, '')); return p.startsWith(prefix) ? p.slice(prefix.length) : p; };

// Unified diff -> added lines (with line numbers) and removed lines. Headers are
// only read between `diff --git` and the first hunk, so content lines that happen
// to start with `--- ` or `+++ ` are never mistaken for file names.
export function parseDiff(diff) {
  const added = [], removed = [];
  let file = '', line = 0, inHunk = false;
  for (const l of diff.split('\n')) {
    if (l.startsWith('diff --git ')) { inHunk = false; file = ''; continue; }
    if (l.startsWith('@@')) { inHunk = true; line = Number(/\+(\d+)/.exec(l)?.[1] ?? 0); continue; }
    if (!inHunk) {
      if (l.startsWith('+++ ')) { const f = headerPath(l.slice(4), 'b/'); if (f !== '/dev/null') file = f; }
      else if (l.startsWith('--- ') && !file) { const f = headerPath(l.slice(4), 'a/'); if (f !== '/dev/null') file = f; }
      continue;
    }
    if (l.startsWith('+')) added.push({ file, line: line++, text: l.slice(1) });
    else if (l.startsWith('-')) removed.push({ file, text: l.slice(1) });
    else if (l.startsWith(' ')) line++;
  }
  return { added, removed };
}

// `git diff --name-status -z` -> deleted paths.
export function deletedPaths(nameStatus) {
  const t = nameStatus.split('\0'), deleted = [];
  for (let i = 0; i < t.length - 1;) {
    const status = t[i];
    if (/^[RC]/.test(status)) i += 3;
    else { if (status === 'D') deleted.push(t[i + 1]); i += 2; }
  }
  return deleted;
}

export function scan({ added, removed, deleted = [] }, { ignored = () => false, merge = false } = {}) {
  const hard = [], floor = [];
  const at = (x) => `${x.file}:${x.line}  ${x.text.trim().slice(0, 90)}`;
  // A line removed somewhere in this change and re-added elsewhere is a move, not new.
  const gone = new Map();
  for (const x of removed) gone.set(x.text.trim(), (gone.get(x.text.trim()) ?? 0) + 1);
  const moved = (x) => { const k = x.text.trim(), n = gone.get(k) ?? 0; if (n) gone.set(k, n - 1); return n > 0; };
  for (const x of added) {
    if (ignored(x.file)) continue;
    if (CONFLICT.test(x.text)) hard.push(`conflict marker     ${at(x)}`);
    if (!CODE.test(x.file)) continue;
    if (DEBUG_TAG.test(x.text)) hard.push(`debug tag left in   ${at(x)}`);
    if (merge) continue;
    const kind = SUPPRESSION.test(x.text) ? 'silenced checker' : STUB.test(x.text) ? 'unfinished stub' : TEST.test(x.file) && SKIP.test(x.text) ? 'test skipped' : null;
    if (kind && !moved(x)) floor.push(`${kind.padEnd(19)} ${at(x)}`);
  }
  if (!merge) {
    for (const f of deleted) if (!ignored(f) && TEST.test(f)) floor.push(`test file deleted   ${f}`);
    // Net assertion loss across the test files that remain (moving one between files is not a loss).
    let net = 0; const files = new Set();
    for (const x of removed) if (TEST.test(x.file) && !deleted.includes(x.file) && !ignored(x.file) && ASSERTION.test(x.text)) { net--; files.add(x.file); }
    for (const x of added) if (TEST.test(x.file) && !ignored(x.file) && ASSERTION.test(x.text)) net++;
    if (net < 0) floor.push(`assertions removed  ${-net} net, in ${[...files].join(', ')}`);
  }
  return { hard, floor };
}

export const floorOk = (message) => /\[floor-ok:\s*[^\]\s][^\]]*\]/.test(message);

function selfTest() {
  const diff = ['diff --git a/src/a b.js b/src/a b.js', '--- a/src/a b.js\t', '+++ b/src/a b.js\t', '@@ -0,0 +1,2 @@', '+// @ts-ignore', "+console.log('[DEBUG-a4f2]');"].join('\n');
  const r = scan(parseDiff(diff));
  const ok = r.hard.length === 1 && r.floor.length === 1 && floorOk('x [floor-ok: vendored]') && !floorOk('x [floor-ok: ]');
  console.log(ok ? `commit-gate ${VERSION}: self-test passed` : 'commit-gate: SELF-TEST FAILED');
  process.exit(ok ? 0 : 1);
}

function main() {
  if (process.argv[2] === '--self-test') return selfTest();
  const git = (...a) => execFileSync('git', ['-c', 'core.quotepath=off', ...a], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  let root, parsed, merge = false;
  try {
    root = git('rev-parse', '--show-toplevel').trim();
    const opts = ['--cached', '--no-color', '--no-ext-diff', '-M', '--src-prefix=a/', '--dst-prefix=b/', '--no-relative'];
    parsed = parseDiff(git('diff', ...opts, '--unified=0'));
    parsed.deleted = deletedPaths(git('diff', ...opts, '--name-status', '-z'));
    try { git('rev-parse', '-q', '--verify', 'MERGE_HEAD'); merge = true; } catch { /* not a merge */ }
  } catch (e) {
    process.stderr.write(`commit-gate: skipped, git failed (${e.message.split('\n')[0]})\n`);
    process.exit(0);
  }
  const self = path.relative(root, fileURLToPath(import.meta.url)).split(path.sep).join('/');
  const { hard, floor } = scan(parsed, { ignored: loadIgnore(root, self.startsWith('..') ? [] : [self]), merge });
  const msgFile = process.argv[2];
  const message = msgFile && fs.existsSync(msgFile) ? fs.readFileSync(msgFile, 'utf8').split('\n').filter((l) => !l.startsWith('#')).join('\n') : '';
  const list = (xs) => xs.slice(0, 15).map((x) => `  - ${x}`).join('\n') + (xs.length > 15 ? `\n  - ...and ${xs.length - 15} more` : '');
  if (hard.length) {
    process.stderr.write(`commit-gate: this commit would include things that must never be committed:\n${list(hard)}\nRemove them, then commit again.\n`);
    process.exit(1);
  }
  if (floor.length && !floorOk(message)) {
    process.stderr.write(`commit-gate: this commit lowers the quality bar:\n${list(floor)}\nFix the code. If a finding is deliberate, say why in the commit message with [floor-ok: <reason>], or list the path in .floorignore.\n`);
    process.exit(1);
  }
  process.exit(0);
}

const invoked = process.argv[1] && path.resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
if (invoked) main();
