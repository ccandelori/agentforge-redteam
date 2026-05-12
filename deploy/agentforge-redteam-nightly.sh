#!/usr/bin/env bash
#
# Nightly red-team session script. Invoked by the systemd timer at 02:00 UTC.
#
# Responsibilities:
#   1. Re-check the kill switch — if an operator tripped it during the day, we
#      skip cleanly (the timer fires again tomorrow).
#   2. Run the regression harness against the current target_sha so any new
#      target build that broke a fix is caught.
#   3. (Future) Start a fresh orchestrator session once `start-session` is wired
#      through to the LangGraph driver. The placeholder below documents intent
#      without running half-built code.
#
# All side effects route through the audited tool wrapper and land in SQLite.

set -euo pipefail

cd "$(dirname "$0")/.."

REPO="/srv/agentforge-redteam"
UV="/usr/local/bin/uv"
TARGET_SHA="${TARGET_SHA:-$(date -u +%Y-%m-%dT%H%M%SZ)}"

echo "[$(date -u +%FT%TZ)] nightly: starting (target_sha=$TARGET_SHA)"

# Step 1 — bail early if the operator tripped the kill switch.
STATUS_EXIT=0
"$UV" run agentforge-redteam status >/dev/null 2>&1 || STATUS_EXIT=$?
if [ "$STATUS_EXIT" -ne 0 ]; then
    echo "[$(date -u +%FT%TZ)] nightly: kill switch enabled — skipping"
    exit 0
fi

# Step 2 — replay every promoted regression case against the current target.
# The CLI exits 1 if any case regressed (CI-gate-style). We treat that as the
# desired failure mode of the nightly run, NOT as a script error to retry.
REGRESS_EXIT=0
"$UV" run agentforge-redteam regress --target-sha "$TARGET_SHA" || REGRESS_EXIT=$?
case "$REGRESS_EXIT" in
    0) echo "[$(date -u +%FT%TZ)] nightly: regression suite held" ;;
    1) echo "[$(date -u +%FT%TZ)] nightly: REGRESSED — see /ui/queue for human review" ;;
    *) echo "[$(date -u +%FT%TZ)] nightly: regress exited $REGRESS_EXIT — unexpected" ; exit "$REGRESS_EXIT" ;;
esac

# Step 3 — start a fresh red-team session against the configured target.
# Exit codes from `start-session` are operationally meaningful:
#   0 = clean completion (or budget/no-progress/no-candidates halt)
#   1 = kill switch tripped or canary failed during the run
#   2 = recursion limit hit (orchestrator failed to halt)
#   3 = config error (operator must fix .env)
SESSION_EXIT=0
"$UV" run agentforge-redteam start-session \
    --target droplet_prod \
    --cost-cap-cents 500 \
    --categories prompt-injection-indirect,data-exfiltration,tool-misuse \
    --max-campaigns 5 || SESSION_EXIT=$?
case "$SESSION_EXIT" in
    0) echo "[$(date -u +%FT%TZ)] nightly: session complete" ;;
    1) echo "[$(date -u +%FT%TZ)] nightly: session halted (kill_switch/canary)" ;;
    2) echo "[$(date -u +%FT%TZ)] nightly: session hit recursion limit" ;;
    3) echo "[$(date -u +%FT%TZ)] nightly: session config error — operator must fix .env" ;;
    *) echo "[$(date -u +%FT%TZ)] nightly: session exited $SESSION_EXIT — unexpected" ; exit "$SESSION_EXIT" ;;
esac

echo "[$(date -u +%FT%TZ)] nightly: complete"
