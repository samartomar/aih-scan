"""Offline test executable for the analyzer's native Gemini and OpenCode transports."""
import json
import os
from pathlib import Path
import sys


def main():
    log, client, *argv = sys.argv[1:]
    if argv == ["--version"]:
        print("1.19.0")
        return
    if argv == ["debug", "config"]:
        print(os.environ["OPENCODE_CONFIG_CONTENT"])
        return
    if argv[:2] == ["auth", "list"]:
        print("1 credential")
        return
    prompt = sys.stdin.buffer.read().decode("utf-8")
    with Path(log).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps([argv, prompt]) + "\n")
    partition = prompt.partition("AIH_SCAN_TASKS\n")
    result = {"findings": []}
    if partition[1]:
        tasks, _ = json.JSONDecoder().raw_decode(partition[2])
        result = {"items": [{"key": task["key"], "result": {"findings": []}}
                            for task in reversed(tasks)]}
    text = json.dumps(result)
    reply = {"response": text} if client == "gemini" else {"part": {"type": "text", "text": text}}
    print(json.dumps(reply))


if __name__ == "__main__":
    main()
