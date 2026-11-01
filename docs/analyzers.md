# External analyzers: SkillSpector and Cisco skill-scanner

Scan routes Text, Code and Config parts (`aih-scan-routing/1`) to SkillSpector, its
primary external analyzer. Cisco skill-scanner is an optional second opinion that runs
only when a request names it. `aih-trust-lint` is built in and always runs. Both external
analyzers are installed by you; Scan never downloads or installs them.

| Tool | Pinned release | Runs | Counts for coverage |
|---|---|---|---|
| SkillSpector | 2.13.2 (NVIDIA/SkillSpector tag `v2.13.2`, commit `abd82935b67f765a9541013c0866c6349251dcdf`) | by default | yes |
| Cisco skill-scanner | 2.3.2 (PyPI `cisco-ai-skill-scanner==2.3.2`) | only with `--tools …,cisco` | never |

## Installing

Both are Python command-line tools. The locked runtimes in `tools/analyzers/` pin every
dependency (PyPI packages by hash, SkillSpector by commit); install either one with [uv](https://docs.astral.sh/uv/):

```sh
UV_PROJECT_ENVIRONMENT=$HOME/.aih-scan/skillspector \
  uv sync --project tools/analyzers/skillspector --locked --no-install-project
UV_PROJECT_ENVIRONMENT=$HOME/.aih-scan/cisco \
  uv sync --project tools/analyzers/cisco-skill-scanner --locked --no-install-project
```

Without the repository, `uv tool install "skillspector @ git+https://github.com/NVIDIA/SkillSpector@abd82935b67f765a9541013c0866c6349251dcdf"`
and `uv tool install cisco-ai-skill-scanner==2.3.2` put the commands in `~/.local/bin`
(unlocked transitive dependencies).

## How Scan finds them

For each tool Scan looks, in order, at:

1. `AIH_SCAN_SKILLSPECTOR` / `AIH_SCAN_SKILL_SCANNER`: an absolute path to the executable,
   or `none` to disable the tool (it is then reported `not-run`, reason `unavailable`);
2. the directories on your `PATH`;
3. the usual install folders (`~/.local/bin`, `/usr/local/bin`, `/usr/bin`, Homebrew).

On Windows only `skillspector.exe` and `skill-scanner.exe` are accepted (the console
entry points a Python environment creates in `Scripts\`), never a `.cmd`, `.bat` or
`.ps1` shim. Before scanning, Scan asks the found executable for `--version` and refuses
any other release (`not-run`, reason `unavailable`, with the version found in the
result's notes). Nothing is run from the scanned content.

## How a run works

Each item is copied into Scan's own read-only working copy; the analyzers read only that
copy. Each analyzer runs natively (no Docker, Windows included) as one shell-free child
process whose whole process tree is contained (a POSIX process group, or a Windows Job
Object with kill-on-close), limited to ten minutes per tool and item, and ended at once
when you cancel. A timeout is `not-run` with reason `timeout` and makes that item
`partial`; cancelling returns `cancelled` and keeps the finished results. Reports are
written to a private scratch folder outside the working copy and the output folder, read
with a size bound, and removed.

### SkillSpector

```
skillspector scan <working-copy> --format json --output <scratch>/report.json [--no-llm]
```

- **Static (default).** `--no-llm`, and a scrubbed environment: only what Python needs
  to start, a private HOME/TEMP, no proxy, credential, provider or Python loader
  variables. Scan also sets `SKILLSPECTOR_OSV_TIMEOUT=0`, which stops SkillSpector's own
  live OSV.dev lookup before any request: known vulnerabilities come only from the
  separate `checkAdvisories` call, so SkillSpector's SC4 findings are not part of a scan,
  and the disabled lookup is not counted as a coverage gap. The analysis makes no network
  call. Scan never passes `--transitive*`, `--mcp-registry`, `--use-shipped-baseline`
  (author-supplied suppressions) or a URL input.
- **AI (`--mode ai`).** The static checks plus SkillSpector's AI pass, using the AI you
  already set up through SkillSpector's own settings, passed through unchanged:
  `SKILLSPECTOR_PROVIDER`, `SKILLSPECTOR_MODEL` and the provider's variables. Scan adds no
  model, budget or credential store and records only how the AI ran (`cli`, `local` or
  `provider`), the provider and the model, never a credential. The command says before
  scanning that the scanned content is sent to that AI.

  AI counts as set up when `SKILLSPECTOR_PROVIDER` names a supported provider and its
  required settings are present:

  | Provider | Via | Needs |
  |---|---|---|
  | `claude_cli`, `gemini_cli`, `opencode_cli` | cli | the `claude`, `gemini` or `opencode` CLI on PATH, signed in |
  | `ollama` | local | a local Ollama service |
  | `openai_compatible` | local for a loopback `SKILLSPECTOR_COMPAT_BASE_URL`, else provider | `SKILLSPECTOR_COMPAT_BASE_URL` |
  | `openai`, `anthropic`, `anthropic_proxy`, `azure_openai`, `bedrock`, `nv_build`, `nv_inference` | provider | the provider's key or profile variables |

  Scan never picks a provider for you: with `SKILLSPECTOR_PROVIDER` unset (or naming an
  upstream-disabled provider such as `codex_cli`), the result says "AI not available here"
  with the reason, SkillSpector runs static only, nothing is sent to an AI, and coverage is
  measured exactly as for a static scan. When AI is set up but SkillSpector's AI pass does
  not run or complete, the static findings are kept and the item is `partial` (reason
  `failed`).
- **Results.** SkillSpector's rule id, severity and confidence are kept; each finding is
  placed at its primary location's file and line, which must be a file of the item routed
  to SkillSpector. Codes come from `aih-codes/1` (`codes.tools.skillspector`), SkillSpector's
  own risk score is ignored and `aih-risk/1` scores the findings. Exit 1 (SkillSpector's own
  risk threshold) is a finished run; exit 2, a missing report, a failed analysis or another
  version are `not-run`, reason `failed`. When SkillSpector reports that it could not fully
  inspect a routed file, the result carries an unsigned note; gaps on files no tool is
  routed (binaries, dependency manifests) are not reported as gaps.

### Cisco skill-scanner

```
cd <working-copy> && skill-scanner scan . --use-behavioral --format json --output-json <scratch>/cisco.json
```

Always static, also in AI mode, with the scrubbed environment; Scan never passes
`--use-llm`, `--use-virustotal`, `--vt-upload-files`, `--use-aidefense`, `--use-osv`,
`--enable-meta`, `--adjudicate` or `--system-one-endpoint`, and never uses `scan-repo`.
Cisco reads skills: an item without a root `SKILL.md` is `not-applicable` (its lenient
fallback reports findings against a `SKILL.md` that does not exist). Its findings use
SARIF, `aih-codes/1` (by Cisco category, `codes.categories.cisco`) and `aih-risk/1` like any
tool's, with cross-tool deduplication: the same code, file and line from two tools counts
once. Cisco has no confidence field. Its unavailable, failed, timed-out or not-applicable
outcomes are listed, but Cisco never makes required coverage partial.

#### Behavioral analysis does not execute supplied code

`--use-behavioral` is routed because the pinned 2.3.2 documentation and implementation
establish that it parses and does not run code:

- Upstream documentation at the 2.3.2 commit
  (`cisco-ai-defense/skill-scanner@f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1`,
  `docs/architecture/analyzers/behavioral-analyzer.md`): "uses static code analysis with
  AST parsing and dataflow tracking"; "**No Code Execution**: All analysis is static (AST
  parsing only)"; "Execution model: Static AST/dataflow analysis only (no runtime code
  execution)"; its comparison table lists the behavioral analyzer's code execution as "No".
- Installed 2.3.2 implementation: `skill_scanner/core/analyzers/behavioral_analyzer.py`
  ("Detects threats through code analysis without execution"; Python by AST dataflow,
  shell by lightweight taint tracking). Its parsers use `ast.parse` only
  (`core/static_analysis/parser/python_parser.py`, `interprocedural/call_graph_analyzer.py`,
  `context_extractor.py` and the Python shell-semantics modules). Every `subprocess`,
  `os.system`, `exec`, `eval`, `runpy`, `__import__`, `Popen`, `ctypes` or `pickle.load`
  occurrence in `core/static_analysis` and the behavioral analyzer is a sink name or pattern
  used for detection, not a call. `core/analyzer_factory.py` builds the analyzer for
  `--use-behavioral` with LLM alignment verification left off, so it adds no network use.
- Scan's own tests run the real 2.3.2 scanner with `--use-behavioral` on fixtures whose
  scripts, hooks, package scripts, Python module and compiled module would each leave a
  sentinel file if anything executed or imported them, with the network removed; no
  sentinel appears.

**Supplied `.pyc` files.** Cisco's always-on bytecode analyzer (not the behavioral one)
checks a supplied `.pyc` against its sibling `.py`: after validating the header it reads
the code object with `marshal.load` and compiles the `.py` source to compare
(`core/analyzers/bytecode_analyzer.py`). Neither step executes code, but Python documents
`marshal` as not secure against maliciously constructed data, which can at worst crash the
Cisco process. Scan keeps `.pyc` files in what Cisco reads, so that Cisco's
bytecode-tampering check still works: a crash is contained to the Cisco child process and
reported as a `failed` Cisco outcome, which never affects required coverage. Callers who
do not want this can leave Cisco unselected (the default). Scan routes `.pyc` files to no
tool; they are listed in `notAnalysed` with `secretsChecked: false`.

## Platform notes

Native Windows runs use the same command lines with `.exe` entry points and a Windows Job
Object. The command construction is covered by unit tests; the real analyzers have been
exercised on Linux x64 only.
