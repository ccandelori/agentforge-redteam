#!/usr/bin/env bash
#
# AgentForge Red Team — laptop-side deploy script.
#
# Runs on your laptop. Builds the Vue SPA, ships the repo to the droplet,
# restarts the systemd web service. Pairs with deploy/install.sh which runs
# once on the droplet for first-time provisioning.
#
# Usage:
#   ./deploy/push.sh                    # full deploy: build + sync + restart
#   ./deploy/push.sh --skip-build       # backend-only changes (no SPA rebuild)
#   ./deploy/push.sh --skip-restart     # ship files only; don't bounce service
#   ./deploy/push.sh --skip-tests       # don't run pytest before pushing
#   ./deploy/push.sh --host 1.2.3.4     # override droplet host
#   ./deploy/push.sh --user root        # override ssh user
#   ./deploy/push.sh -h | --help        # this message
#
# Defaults:
#   DROPLET_HOST = $DROPLET_HOST env var, else 104.248.232.22
#   DROPLET_USER = $DROPLET_USER env var, else root
#   REPO_ROOT    = /srv/agentforge-redteam (on the droplet)

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors (degrade gracefully on dumb TTYs / CI)
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ "${TERM:-}" != "dumb" ]; then
    BOLD=$(printf '\033[1m'); GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m'); RED=$(printf '\033[31m')
    DIM=$(printf '\033[2m'); NC=$(printf '\033[0m')
else
    BOLD=""; GREEN=""; YELLOW=""; RED=""; DIM=""; NC=""
fi

step() { printf "${BOLD}==>${NC} %s\n" "$1"; }
ok()   { printf "  ${GREEN}OK${NC}    %s\n" "$1"; }
warn() { printf "  ${YELLOW}WARN${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$1" >&2; exit 1; }
hint() { printf "  ${DIM}%s${NC}\n" "$1"; }

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
DROPLET_HOST="${DROPLET_HOST:-104.248.232.22}"
DROPLET_USER="${DROPLET_USER:-root}"
REPO_ROOT_REMOTE="/srv/agentforge-redteam"
SKIP_BUILD=0
SKIP_RESTART=0
SKIP_TESTS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build)   SKIP_BUILD=1; shift ;;
        --skip-restart) SKIP_RESTART=1; shift ;;
        --skip-tests)   SKIP_TESTS=1; shift ;;
        --host)         DROPLET_HOST="$2"; shift 2 ;;
        --user)         DROPLET_USER="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//; s/^#$//'
            exit 0
            ;;
        *) fail "unknown arg: $1 (use --help)" ;;
    esac
done

REPO_ROOT_LOCAL="$(cd "$(dirname "$0")/.." && pwd)"
SSH_TARGET="$DROPLET_USER@$DROPLET_HOST"

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
step "preflight"
cd "$REPO_ROOT_LOCAL"

if [ ! -d "src/agentforge_redteam/web/frontend" ]; then
    fail "expected src/agentforge_redteam/web/frontend; run from a repo checkout"
fi

# SSH agent must have a usable key. BatchMode=yes refuses to prompt.
if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_TARGET" 'true' 2>/dev/null; then
    fail "ssh $SSH_TARGET failed. Load your key (\`ssh-add\`) or check --host/--user."
fi
ok "ssh to $SSH_TARGET works"

if [ "$SKIP_TESTS" -eq 0 ]; then
    if uv run pytest tests/ -q --no-header >/tmp/push.pytest 2>&1; then
        ok "pytest: $(tail -1 /tmp/push.pytest | tr -d '\r')"
    else
        tail -10 /tmp/push.pytest | sed 's/^/        /'
        fail "pytest failed. Use --skip-tests to push anyway."
    fi
else
    warn "skipping pytest (--skip-tests)"
fi

# ---------------------------------------------------------------------------
# 1. Build the SPA
# ---------------------------------------------------------------------------
if [ "$SKIP_BUILD" -eq 0 ]; then
    step "build SPA (vite)"
    cd src/agentforge_redteam/web/frontend

    # Refresh node_modules if package.json is newer than the install marker.
    NEED_INSTALL=0
    if [ ! -d node_modules ]; then
        NEED_INSTALL=1
    elif [ -f package.json ] && [ -f node_modules/.package-lock.json ]; then
        if [ "package.json" -nt "node_modules/.package-lock.json" ]; then
            NEED_INSTALL=1
        fi
    fi

    if [ "$NEED_INSTALL" -eq 1 ]; then
        hint "running npm install (package.json changed or node_modules missing)"
        npm install --silent 2>&1 | tail -3 | sed 's/^/        /'
    fi

    if ! npm run build > /tmp/push.build 2>&1; then
        tail -20 /tmp/push.build | sed 's/^/        /'
        fail "vite build failed"
    fi
    # Surface the bundle sizes line.
    grep -E "dist/(index\.html|assets/index-)" /tmp/push.build | tail -3 | sed 's/^/  /' || true
    ok "vite build complete -> src/agentforge_redteam/web/frontend/dist/"
    cd "$REPO_ROOT_LOCAL"
else
    warn "skipping vite build (--skip-build)"
    if [ ! -f src/agentforge_redteam/web/frontend/dist/index.html ]; then
        fail "no built dist/ and --skip-build was passed; nothing to ship"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Rsync to droplet
# ---------------------------------------------------------------------------
step "rsync repo -> $SSH_TARGET:$REPO_ROOT_REMOTE"

# --delete: mirror state, drops anything stale (e.g. removed view files).
# Excludes: build-time dirs, local DB, secrets, taskmaster state.
rsync -az --delete \
    --exclude '.venv' \
    --exclude 'var' \
    --exclude '__pycache__' \
    --exclude '.git' \
    --exclude '.taskmaster' \
    --exclude '.cache' \
    --exclude '.pytest_cache' \
    --exclude '.mypy_cache' \
    --exclude '.ruff_cache' \
    --exclude '.DS_Store' \
    --exclude '*.pyc' \
    --exclude 'src/agentforge_redteam/web/frontend/node_modules' \
    --exclude 'docs/NEXT-SESSION.md' \
    --exclude 'Week 3*.pdf' \
    -e 'ssh -o BatchMode=yes' \
    "$REPO_ROOT_LOCAL/" \
    "$SSH_TARGET:$REPO_ROOT_REMOTE/" 2>&1 | tail -1 | sed 's/^/  /'
ok "rsync complete"

# ---------------------------------------------------------------------------
# 3. Re-chown and restart the service
# ---------------------------------------------------------------------------
if [ "$SKIP_RESTART" -eq 0 ]; then
    step "restart on droplet"
    ssh -o BatchMode=yes "$SSH_TARGET" 'bash -s' <<'REMOTE' 2>&1 | sed 's/^/  /'
set -euo pipefail
# Re-chown anything rsync just landed as root.
chown -R agentforge-redteam:agentforge-redteam /srv/agentforge-redteam

# Apply nginx config if it changed (idempotent). Picks the TLS-enabled
# variant when a Let's Encrypt cert exists for the sslip.io hostname,
# else falls back to the HTTP-only fallback. The selection lives here so
# the laptop side stays single-source-of-truth for which conf is live.
NGINX_SRC=/srv/agentforge-redteam/deploy/nginx-http-only.conf
if [ -f /etc/letsencrypt/live/104-248-232-22.sslip.io/fullchain.pem ]; then
    NGINX_SRC=/srv/agentforge-redteam/deploy/nginx-tls.conf
fi
echo "nginx: using $(basename "$NGINX_SRC")"
if ! cmp -s "$NGINX_SRC" /etc/nginx/sites-available/agentforge-redteam; then
    install -m 0644 "$NGINX_SRC" /etc/nginx/sites-available/agentforge-redteam
    nginx -t 2>&1 | tail -2
    systemctl reload nginx
    echo "nginx: reloaded (config drift detected)"
else
    echo "nginx: config unchanged, no reload"
fi

# Cert-renewal deploy hook: certbot.timer renews every ~12h; nginx must
# pick up the new fullchain.pem without manual intervention. Idempotent
# write — only updates the file if content differs.
HOOK=/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
HOOK_BODY='#!/bin/sh
# Installed by deploy/push.sh — reload nginx after Lets Encrypt renewal.
systemctl reload nginx
'
mkdir -p "$(dirname "$HOOK")"
if ! [ -f "$HOOK" ] || [ "$(cat "$HOOK")" != "$HOOK_BODY" ]; then
    printf '%s' "$HOOK_BODY" > "$HOOK"
    chmod 0755 "$HOOK"
    echo "certbot: deploy hook installed"
fi

# Apply systemd unit drift (idempotent).
DRIFTED=0
for unit in agentforge-redteam-web.service agentforge-redteam-nightly.service agentforge-redteam-nightly.timer; do
    if ! cmp -s "/srv/agentforge-redteam/deploy/$unit" "/etc/systemd/system/$unit"; then
        install -m 0644 "/srv/agentforge-redteam/deploy/$unit" "/etc/systemd/system/$unit"
        DRIFTED=1
    fi
done
[ "$DRIFTED" -eq 1 ] && { systemctl daemon-reload; echo "systemd: daemon-reload (unit drift detected)"; } || echo "systemd: unit files unchanged"

# Run any pending Alembic migrations before bouncing the service. PLATFORM_DB_PATH
# comes from /etc/agentforge-redteam/redteam.env so we source it.
# Use `bash -lc` with cd so alembic resolves relative paths (script_location)
# from the repo root, not from /root where ssh lands.
set -a; . /etc/agentforge-redteam/redteam.env; set +a
sudo -u agentforge-redteam -H \
    XDG_CACHE_HOME=/srv/agentforge-redteam/.cache \
    PLATFORM_DB_PATH="$PLATFORM_DB_PATH" \
    bash -c 'cd /srv/agentforge-redteam && /srv/agentforge-redteam/.venv/bin/alembic upgrade head' 2>&1 | tail -3

systemctl restart agentforge-redteam-web.service

# Poll the loopback healthz endpoint until uvicorn is actually accepting
# connections. Plain `sleep N` raced uvicorn's cold-start on the 2GB droplet.
# Give up after 15s — at that point something's wrong.
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -fsS -m 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
        echo "service: active (healthz 200 after ${i}s)"
        exit 0
    fi
    sleep 1
done
echo "service: NOT serving healthz after 15s — check journalctl -u agentforge-redteam-web.service" >&2
exit 1
REMOTE
    ok "restart complete"
else
    warn "skipping service restart (--skip-restart)"
fi

# ---------------------------------------------------------------------------
# 4. Public smoke
# ---------------------------------------------------------------------------
step "public smoke"

# Pick scheme + hostname based on whether the TLS cert is on the droplet.
# sslip.io hostname is required for cert SAN matching; bare IP would fail
# verification even though the cert is valid.
if ssh -o BatchMode=yes "$SSH_TARGET" 'test -f /etc/letsencrypt/live/104-248-232-22.sslip.io/fullchain.pem' 2>/dev/null; then
    SMOKE_URL="https://104-248-232-22.sslip.io"
else
    SMOKE_URL="http://$DROPLET_HOST"
fi
hint "smoke base: $SMOKE_URL"

HEALTH=$(uv run python -c "
import urllib.request as r, urllib.error
try:
    with r.urlopen('$SMOKE_URL/healthz', timeout=10) as resp:
        print(resp.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print('ERR:'+str(e))
" 2>/dev/null)

case "$HEALTH" in
    200) ok "GET $SMOKE_URL/healthz -> 200" ;;
    ERR:*) fail "GET $SMOKE_URL/healthz -> $HEALTH" ;;
    *)   fail "GET $SMOKE_URL/healthz -> HTTP $HEALTH" ;;
esac

UI=$(uv run python -c "
import urllib.request as r, urllib.error
try:
    with r.urlopen('$SMOKE_URL/ui', timeout=10) as resp:
        print(resp.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print('ERR:'+str(e))
" 2>/dev/null)

case "$UI" in
    401) ok "GET $SMOKE_URL/ui -> 401 (auth gate works)" ;;
    *)   warn "GET $SMOKE_URL/ui -> $UI (expected 401)" ;;
esac

# ---------------------------------------------------------------------------
echo
printf "${GREEN}${BOLD}Deploy complete.${NC}\n"
echo "  UI:      $SMOKE_URL/ui"
echo "  Logs:    ssh $SSH_TARGET 'journalctl -u agentforge-redteam-web.service -f'"
