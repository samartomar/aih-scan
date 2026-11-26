import asyncio
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import json
import os
import runpy
import stat
import sys

from pydantic import ValidationError
from skillspector import llm_analyzer_base as native
from skillspector.nodes.analyzers import semantic_security_discovery as detector

PROFILE = "adaptive-ssd/1"
FRAME_BYTES = 2 * 1024 * 1024
MODEL = "k3"
RULES = {"SSD-1", "SSD-2", "SSD-3", "SSD-4"}
SELECTED = False
INFERENCE_COMPLETED = False
QUOTA_REFUSED = False


class AdaptiveSsdInferenceError(RuntimeError):
    """No valid SSD output was available from the selected inference route."""


def verify_source(module, pinned):
    source = Path(module.__file__)
    if source.suffix != ".py" or sha256(source.read_bytes()).hexdigest() != pinned:
        raise AdaptiveSsdInferenceError("Adaptive SSD requires the reviewed SkillSpector detector")


def socket_path():
    path = Path(os.environ.get("AIH_SCAN_SSD_SOCKET", ""))
    if not path.is_absolute():
        raise AdaptiveSsdInferenceError("Adaptive SSD requires an absolute broker socket")
    info = path.lstat()
    parent = path.parent.lstat()
    uid = os.getuid()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or
            not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid or parent.st_mode & 0o077):
        raise AdaptiveSsdInferenceError("Adaptive SSD broker socket is not private")
    return str(path)


async def exchange(path, payload, timeout):
    wire = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(wire) > FRAME_BYTES:
        return {"error": "input-budget"}
    out = None
    try:
        async with asyncio.timeout(timeout):
            incoming, out = await asyncio.open_unix_connection(path, limit=FRAME_BYTES)
            out.write(wire)
            await out.drain()
            line = await incoming.readline()
            if not line.endswith(b"\n") or len(line) > FRAME_BYTES:
                raise AdaptiveSsdInferenceError("Adaptive SSD reply was incomplete")
            reply = json.loads(line)
    except (OSError, TimeoutError, ValueError) as exc:
        raise AdaptiveSsdInferenceError("Adaptive SSD broker exchange failed") from exc
    finally:
        if out is not None:
            out.close()
            await out.wait_closed()
    if not isinstance(reply, dict):
        raise AdaptiveSsdInferenceError("Adaptive SSD reply was invalid")
    return reply


def split_batch(batch):
    lines = batch.content.splitlines(keepends=True)
    if len(lines) > 1:
        middle = len(lines) // 2
        midpoint = batch.start_line + middle
        return (
            replace(batch, content="".join(lines[:middle]), end_line=midpoint - 1),
            replace(batch, content="".join(lines[middle:]), start_line=midpoint,
                    end_line=batch.start_line + len(lines) - 1),
        )
    text = batch.content.rstrip("\r\n")
    if len(text) <= 1:
        raise AdaptiveSsdInferenceError("Adaptive SSD could not fit a minimum source segment")
    col = batch.source_start_column or 0
    middle = len(text) // 2
    line_length = batch.source_line_length or len(text)
    common = {"end_line": batch.start_line, "source_line_length": line_length}
    return (
        replace(batch, content=text[:middle], source_start_column=col,
                source_end_column=col + middle, **common),
        replace(batch, content=text[middle:], source_start_column=col + middle,
                source_end_column=col + len(text), **common),
    )


class AdaptiveSsd(native.LLMAnalyzerBase):
    async def _ainvoke_batch_with_retries(self, batch, prompt, *, retry_outcome=None):
        global SELECTED
        if self.base_prompt != detector.ANALYZER_PROMPT or self.response_schema is not native.LLMAnalysisResult:
            raise AdaptiveSsdInferenceError("Adaptive SSD detector identity changed")
        if self.model != MODEL:
            raise AdaptiveSsdInferenceError("Adaptive SSD requires the selected K3 model")
        SELECTED = True
        return batch, await self._adaptive_findings(batch)

    async def _adaptive_findings(self, batch):
        global INFERENCE_COMPLETED, QUOTA_REFUSED
        self._require_time_remaining()
        remaining = self._remaining_timeout()
        timeout = min(remaining, 300) if remaining is not None else 300
        blob = native.append_output_language_instruction(native.BASE_ANALYSIS_PROMPT.format(
            analyzer_prompt="", file_label=batch.file_label,
            numbered_content=native.number_lines(batch.content, batch.start_line),
        ))
        reply = await exchange(socket_path(), {
            "profile": PROFILE, "instructions": detector.ANALYZER_PROMPT,
            "schema": native.LLMAnalysisResult.model_json_schema(), "document": blob,
            "lines": max(1, len(batch.content.splitlines())), "startLine": batch.start_line,
            "timeoutMs": max(1, int(timeout * 1000)),
        }, timeout)
        if reply.get("error") == "input-budget":
            # Relegate oversized inputs to independently attributable native segments.
            # Mark the original batch successful only if every segment succeeds.
            findings = []
            for part in split_batch(batch):
                findings.extend(await self._adaptive_findings(part))
            unique = {}
            for finding in findings:
                key = (finding.rule_id, finding.file, finding.start_line, finding.end_line, finding.message)
                unique.setdefault(key, finding)
            return list(unique.values())
        if reply.get("error") == "quota-refused":
            QUOTA_REFUSED = True
            raise AdaptiveSsdInferenceError("Adaptive SSD inference quota refused")
        if reply.get("error") == "invalid-output":
            raise native._StructuredResponseValidationError()
        if set(reply) != {"result"}:
            raise AdaptiveSsdInferenceError("Adaptive SSD received no attributable result")
        raw = reply["result"]
        if not isinstance(raw, dict) or set(raw) != {"findings"} or not isinstance(raw["findings"], list):
            raise native._StructuredResponseValidationError()
        try:
            parsed = native.LLMAnalysisResult.model_validate(raw)
        except ValidationError as exc:
            raise native._StructuredResponseValidationError() from exc
        first = batch.start_line
        last = batch.end_line or first + max(1, len(batch.content.splitlines())) - 1
        unique = set()
        for finding in parsed.findings:
            end = finding.end_line if finding.end_line is not None else finding.start_line
            identity = finding.model_dump_json()
            if (finding.rule_id not in RULES or not first <= finding.start_line <= end <= last
                    or identity in unique):
                raise native._StructuredResponseValidationError()
            unique.add(identity)
        findings = self.parse_response(parsed, batch)
        INFERENCE_COMPLETED = True
        return findings


def main():
    if (os.environ.get("AIH_SCAN_AI_PROFILE") != PROFILE or
            os.environ.get("SKILLSPECTOR_MODEL") != MODEL or len(sys.argv) < 3 or
            sys.argv[2] != "scan"):
        raise AdaptiveSsdInferenceError("Invalid adaptive SSD bootstrap configuration")
    verify_source(detector, "12239663fad4520cce7638043818f824767e11e4d2239b5d4ee5bf4f9d9e249b")
    verify_source(native, "c5a5e37d74f5a3377c6688dbf518769b4653819d84595024b0182f68ba18bf3e")
    socket_path()
    # Only this trusted detector's constructor changes; every other analyzer
    # continues to resolve its original LLMAnalyzerBase.
    detector.LLMAnalyzerBase = AdaptiveSsd
    from skillspector import cli
    original_write = cli._write_result

    def write_result(result, output, format):
        body = result.get("report_body")
        if isinstance(body, str) and body:
            try:
                report = json.loads(body)
            except ValueError:
                report = None
            if isinstance(report, dict) and isinstance(report.get("metadata"), dict):
                statuses = report.get("analysis_completeness", {}).get("analyzer_statuses", [])
                no_tasks = any(
                    isinstance(status, dict) and status.get("analyzer_id") == detector.ANALYZER_ID
                    and status.get("status") == "not_applicable"
                    and status.get("reason_code") == "no_applicable_files"
                    for status in statuses
                )
                if not (SELECTED or no_tasks):
                    return original_write(result, output, format)
                report["metadata"]["aih_scan_ai_profile"] = PROFILE
                if QUOTA_REFUSED:
                    report["metadata"]["aih_scan_ssd_quota_refused"] = True
                if INFERENCE_COMPLETED:
                    report["metadata"]["aih_scan_ssd_inference_completed"] = True
                result = dict(result, report_body=json.dumps(report, ensure_ascii=False))
        return original_write(result, output, format)

    cli._write_result = write_result
    sys.argv = sys.argv[1:]
    runpy.run_path(sys.argv[0], run_name="__main__")


if __name__ == "__main__":
    try:
        main()
    except AdaptiveSsdInferenceError:
        sys.stderr.write("Adaptive SSD analyzer bootstrap failed.\n")
        sys.exit(2)
