#!/usr/bin/env bash
# Actions signals the step entry PID. Keep this shell alive while the CLI writes
# its seven-row cancellation inventory, and never admit that output as a candidate.
set -euo pipefail
if [ "$#" -ne 6 ]; then exit 2; fi
manifest="$1"
tarball="$2"
consumer="$3"
output="$4"
manifest_sha="$5"
selection="$6"
child=""
cancelled=0
received_signal=""
forward_signal() {
  cancelled=1
  received_signal="$1"
  if [ -n "$child" ]; then kill -s "$1" "$child" 2>/dev/null || true; fi
}
trap 'forward_signal INT' INT
trap 'forward_signal TERM' TERM

run_child() {
  if [ "$cancelled" -ne 0 ]; then return 2; fi
  "$@" &
  child=$!
  # A signal between the admission check and PID assignment still reaches Node.
  if [ "$cancelled" -ne 0 ]; then kill -s "$received_signal" "$child" 2>/dev/null || true; fi
  local status
  while true; do
    if wait "$child"; then status=0; else status=$?; fi
    # Bash wait is interrupted by a trapped signal. Resume waiting for graceful
    # CLI cleanup instead of exiting with a still-running foreground child.
    if ! kill -0 "$child" 2>/dev/null; then break; fi
  done
  child=""
  if [ "$cancelled" -ne 0 ]; then return 2; fi
  return "$status"
}

if run_child node tools/refresh/refresh.mjs run --manifest "$manifest" --scanner-tgz "$tarball" --scanner-install "$consumer" --out "$output"; then
  status=0
else
  status=$?
fi
case "$status" in 0|1) ;; *) exit "$status";; esac
run_child node tools/artifact/refresh-publication.mjs retain "$output" "$tarball" "$consumer"
run_child node tools/artifact/refresh-publication.mjs check "$output" "$consumer" "$manifest_sha" "$selection" transport
printf 'Producer coverage exit: %s; see every terminal row in inventory.json.\n' "$status"
