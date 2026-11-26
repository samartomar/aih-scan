"""Check the pinned analyzer's serialized HTTP requests without opening a network connection."""
import asyncio
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

import httpx2 as httpx
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.response import HTTPResponse


def deny_network(event, args):
    if event == "socket.connect" and args[1][0] in {"127.0.0.1", "::1"}:
        return  # asyncio on Windows uses a loopback socket pair for wakeups.
    if event in {"socket.connect", "socket.getaddrinfo"}:
        raise AssertionError(f"Unexpected network access: {event}")


sys.addaudithook(deny_network)
from skillspector import llm_analyzer_base as native
from skillspector.providers import _agent_cli


def exercise(provider, model, count=2, deployment=None):
    os.environ.update(
        SKILLSPECTOR_PROVIDER=provider, SKILLSPECTOR_MODEL=model,
        OPENAI_API_KEY="fixture", ANTHROPIC_API_KEY="fixture",
        NVIDIA_INFERENCE_KEY="fixture", ANTHROPIC_PROXY_API_KEY="fixture",
        ANTHROPIC_PROXY_ENDPOINT_URL="https://proxy.invalid/endpoint",
        SKILLSPECTOR_COMPAT_API_KEY="fixture", SKILLSPECTOR_COMPAT_BASE_URL="https://fixture.invalid/v1",
        AZURE_OPENAI_ENDPOINT="https://fixture.invalid", AZURE_OPENAI_API_KEY="fixture",
        AWS_ACCESS_KEY_ID="fixture", AWS_SECRET_ACCESS_KEY="fixture",
        AWS_EC2_METADATA_DISABLED="true", AWS_DEFAULT_REGION="us-west-2",
        SKILLSPECTOR_OSV_TIMEOUT="0",
    )
    bridge_path = Path(__file__).resolve().parents[2] / "runtime/provider-batching.py"
    bridge = runpy.run_path(str(bridge_path))
    requests = []
    if deployment:
        os.environ["AZURE_OPENAI_DEPLOYMENT"] = deployment
    deepseek = model == "deepseek-flash"
    if deepseek:
        os.environ.update(SKILLSPECTOR_COMPAT_BASE_URL="https://api.deepseek.com/v1",
                          SKILLSPECTOR_REASONING_EFFORT="none",
                          SKILLSPECTOR_STRUCTURED_OUTPUT_METHOD="function_calling")

    def reply(url, data):
        requests.append((unquote(str(url)), data))
        messages = data["messages"]
        prompt = messages[-1]["content"]
        if isinstance(prompt, list):
            prompt = "\n".join(part.get("text", "") for part in prompt)
        if "AIH_SCAN_TASKS\n" in prompt:
            tasks, _ = json.JSONDecoder().raw_decode(prompt.split("AIH_SCAN_TASKS\n", 1)[1])
            result = {"items": [{"key": t["key"], "result": {"findings": []}} for t in reversed(tasks)]}
        else:
            result = {"findings": []}
        if provider == "bedrock":
            tool = data["toolConfig"]["tools"][0]["toolSpec"]["name"]
            return {"output": {"message": {"role": "assistant", "content": [
                {"toolUse": {"toolUseId": "offline", "name": tool, "input": result}}]}},
                "stopReason": "tool_use", "usage": {"inputTokens": 10, "outputTokens": 10, "totalTokens": 20},
                "metrics": {"latencyMs": 1}}
        if provider in {"anthropic", "anthropic_proxy"}:
            tool = data["tools"][0]["name"] if data.get("tools") else None
            content = [{"type": "tool_use", "id": "fixture", "name": tool, "input": result}] if tool else [
                {"type": "text", "text": json.dumps(result)}]
            return {"id": "fixture", "type": "message", "role": "assistant", "model": model,
                    "content": content, "stop_reason": "tool_use" if tool else "end_turn",
                    "usage": {"input_tokens": 10, "output_tokens": 10}}
        message = {"role": "assistant", "content": json.dumps(result)}
        if data.get("tools"):
            tool = data["tools"][0]["function"]["name"]
            message["tool_calls"] = [{"id": "fixture", "type": "function",
                                      "function": {"name": tool, "arguments": json.dumps(result)}}]
        return {"id": "fixture", "object": "chat.completion", "created": 0, "model": model,
                "choices": [{"index": 0, "message": message,
                             "finish_reason": "tool_calls" if "tool_calls" in message else "stop"}]}

    async def httpx_send(_transport, request):
        return httpx.Response(200, json=reply(request.url, json.loads(await request.aread())))

    def httpx_send_sync(_transport, request):
        return httpx.Response(200, json=reply(request.url, json.loads(request.read())))

    def pool_send(_pool, method, url, body=None, **_kwargs):
        assert method == "POST"
        return HTTPResponse(status=200, headers={"Content-Type": "application/json"},
                            body=io.BytesIO(json.dumps(reply(url, json.loads(body))).encode()),
                            preload_content=False)

    labels = [f"case-{index:03d}" for index in range(count)]

    def run():
        bridge["activate_batching"]()
        analyzer = native.LLMAnalyzerBase("Review the supplied text.", model, timeout=10)
        batches = [native.Batch(file_path=f"{label}.md", content=f"fixture-{label}") for label in labels]
        return asyncio.run(analyzer.arun_batches_detailed(batches))

    if provider.endswith("_cli"):
        name = provider.removesuffix("_cli")
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "requests.jsonl"
            popen = subprocess.Popen
            def start(argv, *args, **kwargs):
                assert argv[0] == name
                fixture = Path(__file__).with_name("capture-agent.py").resolve()
                return popen([sys.executable, "-I", str(fixture), str(log), *argv], *args, **kwargs)
            with patch.object(_agent_cli, "find_binary", return_value=name), patch.object(subprocess, "Popen", start):
                outcome = run()
            assert log.exists(), outcome.failures
            records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        assert len(records) == 1, (provider, len(records), outcome.failures)
        argv, prompt = records[0]
        assert model in argv and all(f"fixture-{label}" in prompt for label in labels), argv
        assert len(outcome.successful) == count, outcome.failures
        return

    with patch.object(httpx.HTTPTransport, "handle_request", httpx_send_sync), \
         patch.object(httpx.AsyncHTTPTransport, "handle_async_request", httpx_send), \
         patch.object(HTTPConnectionPool, "urlopen", pool_send):
        if deployment or provider == "ollama" or deepseek:
            try:
                run()
            except bridge["ModelLimitsUnavailable"]:
                pass
            else:
                raise AssertionError("An unknown deployment reached assessment")
            assert not requests
            with tempfile.TemporaryDirectory() as root:
                registry = Path(root) / "registry.json"
                registry.write_text(json.dumps({"models": {
                    deployment or model: {"context_length": 65536, "max_output_tokens": 4096},
                }}), encoding="utf-8")
                os.environ["SKILLSPECTOR_MODEL_REGISTRY"] = str(registry)
                outcome = run()
        else:
            outcome = run()
    assert len(requests) == 1, (provider, len(requests), outcome.failures)
    url, data = requests[0]
    wire = json.dumps(data["messages"])
    assert all(f"fixture-{label}" in wire for label in labels), (provider, wire)
    if deployment:
        assert deployment in url
    if deepseek:
        assert url == "https://api.deepseek.com/v1/chat/completions"
        assert data.get("max_tokens") == 4096 and "max_completion_tokens" not in data
    elif deployment or provider == "ollama":
        assert 0 < data.get("max_completion_tokens", data.get("max_tokens", 0)) <= 4096, data.keys()
    elif provider != "anthropic_proxy":  # This native adapter strips the model and encodes it in its endpoint.
        assert data.get("model") == model or model in url, (provider, url, data.get("model"))
    assert sorted(b.file_path for b, _ in outcome.successful) == [f"{label}.md" for label in labels], outcome.failures


if __name__ == "__main__":
    exercise(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 2,
             sys.argv[4] if len(sys.argv) > 4 else None)
