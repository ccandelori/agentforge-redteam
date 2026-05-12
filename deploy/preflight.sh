#!/usr/bin/env bash
#
# preflight.sh — laptop-side readiness check before deploying.
#
# Catches the most common pre-deploy mistakes without ever touching the droplet:
#   * dirty working tree (the deploy is git-based; uncommitted work won't ship)
#   * failing tests / lint / type-check (the deploy will faceplant on first request)
#   * missing entries in .env.example for env vars referenced by the deploy
#   * missing SSH agent or unloaded key (the install will hang on the first scp/ssh)
#   * a domain hint (we can't dig your domain from your laptop, but we can warn
#     if you left platform.example.com in nginx.conf)
#
# Run from the repo root:
#   ./deploy/preflight.sh
#
# Exits 0 if all checks pass, 1 if any FAIL, 2 if any WARN-only checks would
# block the operator (e.g., placeholder domain in nginx.conf).

set -uo pipefail

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
NC="\033[0m"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

fail=0
warn=0

PASS() { echo -e "  ${GREEN}OK${NC}    $1"; }
WARN() { echo -e "  ${YELLOW}WARN${NC}  $1"; warn=$((warn + 1)); }
FAIL() { echo -e "  ${RED}FAIL${NC}  $1"; fail=$((fail + 1)); }

heading() { echo; echo "== $1 =="; }

# ---------------------------------------------------------------------------
heading "Working tree"
# ---------------------------------------------------------------------------

if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
    PASS "working tree is clean"
else
    FAIL "uncommitted changes — the droplet pulls from git, your edits will be missed"
    git status --short | head -5 | sed 's/^/        /'
fi

current_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
case "$current_branch" in
    main|master) PASS "on $current_branch" ;;
    "")          FAIL "not in a git repo?" ;;
    *)           WARN "on branch '$current_branch' — the droplet typically tracks main" ;;
esac

if git remote -v 2>/dev/null | grep -q '\bpush'; then
    PASS "git remote configured"
else
    WARN "no git remote — install.sh expects to git clone from one"
fi

# ---------------------------------------------------------------------------
heading "Test + lint gate"
# ---------------------------------------------------------------------------

if uv run pytest tests/ -q --no-header >/tmp/preflight.pytest 2>&1; then
    summary="$(tail -1 /tmp/preflight.pytest | tr -d '\r')"
    PASS "pytest: $summary"
else
    FAIL "pytest failed — see /tmp/preflight.pytest"
    tail -5 /tmp/preflight.pytest | sed 's/^/        /'
fi

if uv run ruff check src/ tests/ alembic/ >/dev/null 2>&1; then
    PASS "ruff check: clean"
else
    FAIL "ruff check has errors"
fi

if uv run ruff format --check src/ tests/ alembic/ >/dev/null 2>&1; then
    PASS "ruff format: clean"
else
    FAIL "ruff format would reformat files — run 'uv run ruff format' first"
fi

if uv run mypy src/ >/dev/null 2>&1; then
    PASS "mypy strict: clean"
else
    FAIL "mypy has errors"
fi

# ---------------------------------------------------------------------------
heading "Deploy artifacts present + readable"
# ---------------------------------------------------------------------------

for f in \
    deploy/README.md \
    deploy/install.sh \
    deploy/agentforge-redteam-web.service \
    deploy/agentforge-redteam-nightly.service \
    deploy/agentforge-redteam-nightly.timer \
    deploy/agentforge-redteam-nightly.sh \
    deploy/nginx.conf \
    deploy/redteam.env.template
do
    if [ -r "$f" ]; then
        PASS "$f"
    else
        FAIL "$f missing or unreadable"
    fi
done

for f in deploy/install.sh deploy/agentforge-redteam-nightly.sh deploy/preflight.sh; do
    if [ -x "$f" ]; then
        PASS "$f is executable"
    else
        FAIL "$f is not chmod +x"
    fi
done

# ---------------------------------------------------------------------------
heading "Domain placeholders"
# ---------------------------------------------------------------------------

if grep -q "platform\.example\.com" deploy/nginx.conf; then
    WARN "deploy/nginx.conf still has placeholder 'platform.example.com' — install.sh has a sed that fixes it on the droplet, but make sure you swap to your real domain before running certbot"
else
    PASS "nginx.conf domain has been customised"
fi

# ---------------------------------------------------------------------------
heading "Environment template <-> .env.example parity"
# ---------------------------------------------------------------------------
# Every env var the deploy template references should also be documented in
# .env.example so dev contributors know it exists.

template_vars="$(grep -E '^[A-Z_][A-Z0-9_]*=' deploy/redteam.env.template | cut -d= -f1 | sort -u)"
example_vars="$(grep -E '^[A-Z_][A-Z0-9_]*=' .env.example | cut -d= -f1 | sort -u)"
missing="$(comm -23 <(echo "$template_vars") <(echo "$example_vars"))"

if [ -z "$missing" ]; then
    PASS ".env.example documents every var the deploy needs"
else
    WARN "deploy template has vars not in .env.example:"
    echo "$missing" | sed 's/^/        /'
fi

# ---------------------------------------------------------------------------
heading "SSH agent"
# ---------------------------------------------------------------------------

if [ -n "${SSH_AUTH_SOCK:-}" ] && ssh-add -l >/dev/null 2>&1; then
    PASS "ssh-agent running and has key(s) loaded: $(ssh-add -l | wc -l | tr -d ' ') key(s)"
else
    WARN "ssh-agent has no keys loaded — run 'ssh-add' before SSHing to the droplet"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "================================================================"
if [ "$fail" -gt 0 ]; then
    echo -e "${RED}${fail} FAIL(s)${NC} — fix before deploying."
    [ "$warn" -gt 0 ] && echo -e "${YELLOW}${warn} WARN(s)${NC}"
    exit 1
fi
if [ "$warn" -gt 0 ]; then
    echo -e "${YELLOW}${warn} WARN(s)${NC} — review above; deploy is otherwise green."
    exit 2
fi
echo -e "${GREEN}All clear.${NC} Ready to SSH to the droplet and run install.sh."
exit 0
