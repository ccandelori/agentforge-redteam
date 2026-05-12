#!/usr/bin/env bash
#
# AgentForge Red Team — first-time droplet provisioning.
#
# Idempotent: every step is safe to re-run. Run as root on the droplet AFTER
# you've git-cloned the repo into REPO_ROOT.
#
# What this does:
#   1. Install OS packages: python3, git, build deps, nginx, certbot, sqlite3.
#   2. Install uv (system-wide, single static binary).
#   3. Create the `agentforge-redteam` system user.
#   4. chown REPO_ROOT, var/, findings/, evals/ to that user.
#   5. As that user: `uv sync --frozen` and `alembic upgrade head`.
#   6. Copy systemd units into /etc/systemd/system/ and daemon-reload.
#   7. STOP. Operator must populate /etc/agentforge-redteam/redteam.env and
#      install nginx.conf before enabling the units.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/srv/agentforge-redteam}"
SERVICE_USER="${SERVICE_USER:-agentforge-redteam}"
ENV_DIR="/etc/agentforge-redteam"

# ---------------------------------------------------------------------------
# Sanity
# ---------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (try: sudo bash deploy/install.sh)" >&2
    exit 1
fi

if [ ! -d "$REPO_ROOT" ]; then
    echo "ERROR: REPO_ROOT=$REPO_ROOT does not exist." >&2
    echo "       Clone the repo there before running this installer." >&2
    exit 1
fi

cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# 1. OS packages
# ---------------------------------------------------------------------------

echo "==> installing apt packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Ubuntu 24.04 ships python3.12 as default; pyproject requires ">=3.11" so
# we accept whichever python3 the distro provides. uv manages its own
# interpreter if it needs a different version (uv python install 3.11).
apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    build-essential \
    git \
    curl \
    ca-certificates \
    sqlite3 \
    nginx \
    certbot \
    python3-certbot-nginx

# ---------------------------------------------------------------------------
# 2. uv (https://github.com/astral-sh/uv)
# ---------------------------------------------------------------------------

echo "==> installing uv"
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # The installer drops uv into /root/.cargo/bin/ — move it to /usr/local/bin
    # so the service user can invoke it without PATH games.
    install -m 0755 "/root/.local/bin/uv" /usr/local/bin/uv
    install -m 0755 "/root/.local/bin/uvx" /usr/local/bin/uvx 2>/dev/null || true
fi
uv --version

# ---------------------------------------------------------------------------
# 3. Service user
# ---------------------------------------------------------------------------

echo "==> ensuring system user '$SERVICE_USER' exists"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ---------------------------------------------------------------------------
# 4. Repo permissions
# ---------------------------------------------------------------------------

echo "==> ensuring writable dirs exist"
mkdir -p "$REPO_ROOT/var" "$REPO_ROOT/findings" "$REPO_ROOT/evals/regressions" \
         "$REPO_ROOT/evals/judge_ground_truth"

echo "==> chowning $REPO_ROOT to $SERVICE_USER"
# RO for the repo itself, RW for the writable dirs. Easier to just chown the
# whole tree to the service user; the systemd unit's ProtectSystem=strict +
# ReadWritePaths still constrains writes at runtime.
chown -R "$SERVICE_USER:$SERVICE_USER" "$REPO_ROOT"
find "$REPO_ROOT" -type d -exec chmod 0755 {} \;
find "$REPO_ROOT" -type f -exec chmod 0644 {} \;
chmod 0755 "$REPO_ROOT/deploy/install.sh" "$REPO_ROOT/deploy/agentforge-redteam-nightly.sh"

# ---------------------------------------------------------------------------
# 5. uv sync + alembic upgrade head (as service user)
# ---------------------------------------------------------------------------

# Service user was created with --no-create-home, so uv's default cache path
# ($HOME/.cache/uv) is unwritable. Point both XDG_CACHE_HOME and the explicit
# UV_CACHE_DIR at a writable subdir of the repo the user already owns.
SVC_ENV="XDG_CACHE_HOME=$REPO_ROOT/.cache UV_CACHE_DIR=$REPO_ROOT/.cache/uv"
mkdir -p "$REPO_ROOT/.cache/uv"
chown -R "$SERVICE_USER:$SERVICE_USER" "$REPO_ROOT/.cache"

echo "==> uv sync (as $SERVICE_USER)"
sudo -u "$SERVICE_USER" -H bash -c "cd $REPO_ROOT && $SVC_ENV /usr/local/bin/uv sync --frozen"

echo "==> alembic upgrade head (as $SERVICE_USER)"
sudo -u "$SERVICE_USER" -H bash -c \
    "cd $REPO_ROOT && $SVC_ENV PLATFORM_DB_PATH=$REPO_ROOT/var/platform.db /usr/local/bin/uv run alembic upgrade head"

# ---------------------------------------------------------------------------
# 6. Systemd units
# ---------------------------------------------------------------------------

echo "==> installing systemd units"
install -m 0644 "$REPO_ROOT/deploy/agentforge-redteam-web.service" /etc/systemd/system/
install -m 0644 "$REPO_ROOT/deploy/agentforge-redteam-nightly.service" /etc/systemd/system/
install -m 0644 "$REPO_ROOT/deploy/agentforge-redteam-nightly.timer" /etc/systemd/system/
systemctl daemon-reload

# ---------------------------------------------------------------------------
# 7. Env directory placeholder
# ---------------------------------------------------------------------------

if [ ! -d "$ENV_DIR" ]; then
    echo "==> creating $ENV_DIR (operator must populate redteam.env)"
    mkdir -p "$ENV_DIR"
    chmod 0750 "$ENV_DIR"
    chown root:"$SERVICE_USER" "$ENV_DIR"
fi

# ---------------------------------------------------------------------------
# Done.
# ---------------------------------------------------------------------------

cat <<EOF

================================================================================
  install.sh complete.

  NEXT STEPS:
    1. cp $REPO_ROOT/deploy/redteam.env.template $ENV_DIR/redteam.env
       chmod 600 $ENV_DIR/redteam.env
       chown $SERVICE_USER:$SERVICE_USER $ENV_DIR/redteam.env
       \$EDITOR $ENV_DIR/redteam.env        # populate REQUIRED values

    2. cp $REPO_ROOT/deploy/nginx.conf /etc/nginx/sites-available/agentforge-redteam
       ln -sf /etc/nginx/sites-available/agentforge-redteam /etc/nginx/sites-enabled/
       rm -f /etc/nginx/sites-enabled/default
       sed -i 's/platform\.example\.com/YOUR.DOMAIN.HERE/g' /etc/nginx/sites-available/agentforge-redteam
       nginx -t && systemctl reload nginx

    3. certbot --nginx -d YOUR.DOMAIN.HERE --redirect --agree-tos -m you@example.com

    4. systemctl enable --now agentforge-redteam-web.service
       systemctl enable --now agentforge-redteam-nightly.timer

    5. Smoke: curl -u operator:PASS https://YOUR.DOMAIN.HERE/healthz

  See deploy/README.md for the full runbook.
================================================================================
EOF
