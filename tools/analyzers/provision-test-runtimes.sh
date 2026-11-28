#!/usr/bin/env bash
set -euo pipefail

runtimes="$RUNNER_TEMP/analyzers"
UV_PROJECT_ENVIRONMENT="$runtimes/skillspector" \
  uv sync --project tools/analyzers/skillspector --locked --no-install-project --python 3.13
UV_PROJECT_ENVIRONMENT="$runtimes/cisco-skill-scanner" \
  uv sync --project tools/analyzers/cisco-skill-scanner --locked --no-install-project --python 3.13
"$runtimes/skillspector/bin/skillspector" --version
"$runtimes/cisco-skill-scanner/bin/skill-scanner" --version

source="$runtimes/SkillSpector-c323ad4c43e3c8f2de051572cc25b2711d11e648.tar.gz"
curl --fail --silent --show-error --location --output "$source" \
  "https://codeload.github.com/NVIDIA/SkillSpector/tar.gz/c323ad4c43e3c8f2de051572cc25b2711d11e648"
echo "ba6db55083e904cd7d44d8b060977eedca5c6463bdb4b0d68681c10a367f5c7d  $source" | sha256sum --check --strict
{
  echo "AIH_SCAN_TEST_SKILLSPECTOR=$runtimes/skillspector/bin/skillspector"
  echo "AIH_SCAN_TEST_SKILL_SCANNER=$runtimes/cisco-skill-scanner/bin/skill-scanner"
  echo "AIH_SCAN_TEST_SKILLSPECTOR_SOURCE=$source"
  echo "AIH_SCAN_REQUIRE_REAL_ANALYZERS=1"
} >> "$GITHUB_ENV"
