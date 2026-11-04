# External analyzers: SkillSpector and Cisco skill-scanner

Scan routes Text, Code and Config parts (`aih-scan-routing/1`) to SkillSpector, its
primary external analyzer. Cisco skill-scanner is an optional second opinion that runs
only when a request names it. `aih-trust-lint` is built in and always runs. Both external
analyzers are installed by you; Scan never downloads or installs them.

Valid UTF-8 files ending in `.kiro.hook` (case-insensitive, without NUL bytes) receive
Text analysis under their original paths, bytes and modes. Existing Config and Code
matches take precedence. Kiro `when`/`then` instructions are inspected as text; Scan
does not execute their actions or extract commands or dependencies from those fields.
Malformed JSON can still receive Text analysis, as other text files do; this does not
establish valid hook configuration. Binary files receive no analysis part. The suffix
does not add a source-discovery layout: use caller-prepared items for a hook item, or
find these files within an owning item or the source's remaining files.

| Tool | Pinned release | Runs | Counts for coverage |
|---|---|---|---|
| SkillSpector | 2.13.3 (NVIDIA/SkillSpector tag `v2.13.3`, commit `38a1dfe93325d2f8bfcd4f8d0241eed706334915`) | by default | yes |
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

Without the repository, `uv tool install "skillspector @ git+https://github.com/NVIDIA/SkillSpector@38a1dfe93325d2f8bfcd4f8d0241eed706334915"`
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
skillspector scan <working-copy> --format json [--output <scratch>/report.json] [--no-llm]
```

On Windows Scan omits `--output`: the pinned SkillSpector does not support safe file
output there. Scan reads its JSON from bounded stdout instead, with the same 64 MiB
report limit and strict UTF-8/JSON validation. Other platforms retain the private report
file. Logs stay on stderr; truncated, malformed or mixed progress/JSON stdout is refused.

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
  | `openai_compatible` | local for a loopback `SKILLSPECTOR_COMPAT_BASE_URL`, else provider | `SKILLSPECTOR_COMPAT_BASE_URL` and `SKILLSPECTOR_COMPAT_API_KEY` (both required, including for a local service) |
  | `openai`, `anthropic`, `anthropic_proxy`, `azure_openai`, `bedrock`, `nv_build`, `nv_inference` | provider | the provider's key or profile variables |

  Scan never picks a provider for you: with `SKILLSPECTOR_PROVIDER` unset (or naming an
  upstream-disabled provider such as `codex_cli`), the result says "AI not available here"
  with the reason, SkillSpector runs static only, nothing is sent to an AI, and coverage is
  measured exactly as for a static scan. When AI is set up but its pass does not complete,
  the item is `partial` (reason `failed`). A usable partial report keeps its static
  findings. If the whole SkillSpector process or report fails, Scan reports the tool
  `not-run` / `failed` and does not retain that failed report's findings; findings from
  other completed tools remain.
  SkillSpector 2.13.3 runs semantic security batches asynchronously through its shared
  concurrency control (`SKILLSPECTOR_MAX_LLM_CONCURRENCY`), preserving batch result
  order. Refused, unfinished or invalid AI responses remain incomplete inspection.
  Scan's ten-minute per-tool deadline remains the outer bound, even though this
  upstream release defaults to an eighteen-minute workflow deadline. Large inputs can
  still time out; parallel execution does not guarantee completion within Scan's limit.
- **Results.** SkillSpector's rule id, severity and confidence are kept; each finding is
  placed at its primary location's file and line, which must be a file of the item routed
  to SkillSpector. Codes come from `aih-codes/1` (`codes.tools.skillspector`), SkillSpector's
  own risk score is ignored and `aih-risk/1` scores the findings. Exit 1 (SkillSpector's own
  risk threshold) is a finished run; exit 2, a missing report, a failed analysis or another
  version are `not-run`, reason `failed`. When SkillSpector reports that it could not fully
  inspect a routed file, the result carries an unsigned note; gaps on files no tool is
  routed (binaries, dependency manifests) are not reported as gaps.

### DeepSeek Flash on Windows

Use SkillSpector's existing `openai_compatible` HTTP provider with the exact model
`deepseek-flash` and endpoint `https://api.deepseek.com`, as specified by
[DeepSeek's API guide](https://api-docs.deepseek.com/quick_start/agent_integrations/).
This uses your DeepSeek API key and API billing, rather than a ChatGPT subscription.
Static analysis stays on your PC; SkillSpector sends the content for its AI pass to DeepSeek.
No agent CLI or model-driven host command executor is involved.

The pinned SkillSpector uses LangChain's schema-bound response parser. DeepSeek does not
support its default `json_schema` response format. Select `function_calling` explicitly:
the functions describe the findings response schema; SkillSpector parses the returned
arguments as data and does not execute them. Also select reasoning effort `none`, which
disables thinking so DeepSeek accepts the forced schema function. This is the
non-thinking route; it changes DeepSeek's default thinking behavior. See
[DeepSeek's request contract](https://api-docs.deepseek.com/api/create-chat-completion/).
Keep other reasoning modes on a separately verified integration; `json_mode` alone does
not add the schema instructions that this pinned analyzer's prompts require.

After installing the locked SkillSpector runtime above and making your key available in
the current terminal as `DEEPSEEK_API_KEY`, run this in PowerShell. Replace the executable,
input and output paths with your own. These settings affect this terminal and its child
processes only; they do not change global defaults or write a credential file.

```powershell
if ([string]::IsNullOrWhiteSpace($env:DEEPSEEK_API_KEY)) { throw 'DEEPSEEK_API_KEY is not set' }
$env:AIH_SCAN_SKILLSPECTOR = 'C:\tools\skillspector\Scripts\skillspector.exe'
$env:SKILLSPECTOR_PROVIDER = 'openai_compatible'
$env:SKILLSPECTOR_COMPAT_BASE_URL = 'https://api.deepseek.com'
$env:SKILLSPECTOR_COMPAT_API_KEY = $env:DEEPSEEK_API_KEY
$env:SKILLSPECTOR_MODEL = 'deepseek-flash'
$env:SKILLSPECTOR_REASONING_EFFORT = 'none'
$env:SKILLSPECTOR_STRUCTURED_OUTPUT_METHOD = 'function_calling'
aih-scan scan 'C:\skills\example' --mode ai --out 'C:\scan-output\example' --json
```

Remove any existing `SKILLSPECTOR_MODEL_<SLOT>` overrides if you intend every analyzer
to use `deepseek-flash`; SkillSpector otherwise honors those more-specific caller settings.
Scan does not select another model or a paid fallback. The pinned SkillSpector's bundled
model metadata predates this alias, so it warns and uses its existing 128,000-token
fallback for context budgeting; it still requests the exact `deepseek-flash` model.

Having the endpoint and key set establishes configuration readiness; authentication,
balance, quota and parsed findings are established only by the run. Failed or malformed
AI analysis cannot establish complete coverage. A usable partial report retains its
findings, but a whole SkillSpector failure (including an exit 2 after a quota error)
is `not-run` / `failed` and its raw report's static findings are not retained. Findings
from other completed tools remain. Inspect coverage and notes, and rerun after resolving
the provider failure; exit zero or an available configuration does not prove complete
AI analysis.

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

Treat this as a real exposure, not only a crash risk: never unmarshal untrusted data in your
own tooling, and when you select Cisco for content you do not trust, run Scan inside an
operating-system sandbox (a container, VM or unprivileged user namespace with no network and
no access to your credentials) so that a flaw in Python's `marshal` or in any analyzer parser
cannot reach the host.

## Isolation

Scan keeps analyzers static and off the network by their own flags and by the environment it
passes (no provider, proxy or credential variables, a private HOME and TEMP); it does not
place them in an operating-system sandbox. Their parsers still read untrusted content with
your user's file-system rights. For untrusted content, run Scan in an isolated environment
(a container or VM without credentials, or on Linux `unshare -rn aih-scan scan <folder>`, which
removes the network for Scan and every analyzer it starts, so only local folders and
tarballs can be scanned and the AI mode has no provider).

## Platform notes

Native Windows runs use `.exe` entry points and a Windows Job Object. SkillSpector's
Windows JSON stdout transport is exercised through the installed package with its real
locked runtime and a synthetic local HTTP service, including malformed responses and
quota errors. This fixture verifies transport and parsing; it does not establish live
provider availability or assessment quality. The real static analyzers have also been
exercised on Linux x64.
