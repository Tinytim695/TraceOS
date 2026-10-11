#!/usr/bin/env bash
# Exercise live-build retry control flow without invoking live-build or sudo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COUNT_DIR=""

fail() {
  echo "[TraceOS] build retry test failed: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$COUNT_DIR" ]]; then
    rm -rf "$COUNT_DIR"
  fi
}
trap cleanup EXIT

load_build() {
  if [[ -n "${COUNT_DIR}" ]]; then
    rm -rf "$COUNT_DIR"
  fi
  # shellcheck disable=SC1091
  TRACEOS_BUILD_UNDER_TEST=1 source "$ROOT/build.sh"
  COUNT_DIR="$(mktemp -d)"
  : >"$COUNT_DIR/builds"
  : >"$COUNT_DIR/purges"
  : >"$COUNT_DIR/configured"
  lb_retry_pause() { return 0; }
  lb_prepare_hooks() { return 0; }
}

mark() {
  local name="$1"
  printf 'x\n' >>"$COUNT_DIR/$name"
}

count() {
  wc -l <"$COUNT_DIR/$1" | tr -d ' '
}

run_failing() {
  local status=0
  set +e
  (
    set -euo pipefail
    "$@"
  ) >/dev/null
  status=$?
  set -e
  printf '%s' "$status"
}

assert_purge_definition_fails_closed() {
  load_build
  local body
  body="$(declare -f lb_clean_purge)"
  [[ "$body" == *"sudo lb clean --purge"* ]] || fail "purge command missing"
  [[ "$body" != *"|| true"* ]] || fail "purge failure is still ignored"
}

assert_initial_cleanup_failure_stops_before_configure() {
  load_build
  lb_clean_purge() { mark purges; return 4; }
  configure_live_build() { mark configured; }
  local status
  status="$(run_failing prepare_live_build)"
  [[ "$status" -ne 0 ]] || fail "initial purge failure did not stop"
  [[ "$(count purges)" -eq 1 ]] || fail "initial purge was not attempted"
  [[ "$(count configured)" -eq 0 ]] || fail "configure ran after failed initial purge"
}

assert_retry_stops_when_purge_fails() {
  load_build
  lb_build_once() { mark builds; return 1; }
  lb_clean_purge() { mark purges; return 9; }
  configure_live_build() { mark configured; }
  local status
  status="$(run_failing run_live_build_attempts)"
  [[ "$status" -ne 0 ]] || fail "failed purge was treated as success"
  [[ "$(count builds)" -eq 1 ]] || fail "expected 1 build before failed purge, got $(count builds)"
  [[ "$(count purges)" -eq 1 ]] || fail "expected 1 purge, got $(count purges)"
  [[ "$(count configured)" -eq 0 ]] || fail "reconfigure ran after failed purge"
}

assert_third_failure_does_not_purge_again() {
  load_build
  lb_build_once() { mark builds; return 1; }
  lb_clean_purge() { mark purges; return 0; }
  configure_live_build() { mark configured; }
  local status
  status="$(run_failing run_live_build_attempts)"
  [[ "$status" -ne 0 ]] || fail "three build failures should stop"
  [[ "$(count builds)" -eq 3 ]] || fail "expected 3 builds, got $(count builds)"
  [[ "$(count purges)" -eq 2 ]] || fail "expected 2 purges, got $(count purges)"
  [[ "$(count configured)" -eq 2 ]] || fail "expected 2 reconfigures, got $(count configured)"
}

assert_successful_retry_after_one_purge() {
  load_build
  lb_build_once() {
    mark builds
    if [[ "$(count builds)" -eq 1 ]]; then
      return 1
    fi
    return 0
  }
  lb_clean_purge() { mark purges; return 0; }
  configure_live_build() { mark configured; }
  run_live_build_attempts
  [[ "$(count builds)" -eq 2 ]] || fail "expected success on attempt 2, builds=$(count builds)"
  [[ "$(count purges)" -eq 1 ]] || fail "expected 1 purge before success, got $(count purges)"
  [[ "$(count configured)" -eq 1 ]] || fail "expected 1 reconfigure before success, got $(count configured)"
}

assert_purge_definition_fails_closed
assert_initial_cleanup_failure_stops_before_configure
assert_retry_stops_when_purge_fails
assert_third_failure_does_not_purge_again
assert_successful_retry_after_one_purge
echo "[TraceOS] build retry cleanup control flow: PASS"
