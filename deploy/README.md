# Deploying AgentForge Red Team to a DigitalOcean droplet

> Single-droplet production deploy. The platform is one Python service (FastAPI under
> uvicorn) plus a SQLite file plus a nightly cron. nginx terminates TLS and reverse-proxies
> to the app. No Docker, no orchestrator. If you outgrow this you'll know.

The artifacts in this directory:

| File | Purpose |
|------|---------|
| `install.sh` | First-time provisioning. Idempotent. Runs on the droplet as root. |
| `agentforge-redteam-web.service` | systemd unit for the web UI (uvicorn). |
| `agentforge-redteam-nightly.service` | systemd unit for the nightly red-team run (oneshot). |
| `agentforge-redteam-nightly.timer` | systemd timer that fires `agentforge-redteam-nightly.service` daily at 02:00 UTC. |
| `agentforge-redteam-nightly.sh` | The script the nightly service invokes. Wraps `agentforge-redteam regress`. |
| `nginx.conf` | TLS reverse proxy with rate limits + security headers. Drop into `/etc/nginx/sites-available/`. |
| `redteam.env.template` | Required env vars in production. Copy to `/etc/agentforge-redteam/redteam.env`. |
| `preflight.sh` | Local readiness check. **Run on your laptop before SSHing to the droplet.** |

The "target" droplet at `https://143.244.157.90` is the AgentForge Clinical Co-Pilot itself
— the system the red-team platform attacks. **Do not deploy this red-team platform onto
the same droplet.** Provision a second droplet (the "platform" droplet) so a compromise of
one can't reach the other on loopback.

---

## 0. Prerequisites — operator checklist

Run from your laptop:

```bash
./deploy/preflight.sh
```

It checks: clean working tree, all tests pass, `.env.example` has every var the deploy
references, you have an SSH agent loaded, and you have a domain ready.

You'll also need:

* DigitalOcean account + a droplet you've already created (Ubuntu 24.04 LTS, 2 GB RAM,
  $12/mo tier is enough for nightly runs at MVP scale).
* A DNS record (`A` or `AAAA`) pointing your domain at the droplet's IP.
* An SSH key uploaded to the droplet for the `root` user (DigitalOcean does this
  automatically when you supply your public key during droplet creation).
* Real values for everything in `deploy/redteam.env.template`.

---

## 1. SSH in and provision

```bash
ssh root@platform.example.com
```

On the droplet:

```bash
# Pull the repo (or scp it over — your call).
apt-get update && apt-get install -y git
git clone https://gitlab.com/<you>/agentforge-redteam.git /srv/agentforge-redteam
cd /srv/agentforge-redteam

# Run the installer. It is idempotent; re-running is safe.
bash deploy/install.sh
```

`install.sh` does:

1. Creates a system user `agentforge-redteam` (no shell, no sudo).
2. `chown -R` `/srv/agentforge-redteam` to that user.
3. Installs Python 3.11+, uv, nginx, certbot, and the `apt` deps for SQLite + httpx.
4. As the service user, runs `uv sync --frozen` against the lockfile.
5. Applies migrations: `uv run alembic upgrade head` (creates `var/platform.db`).
6. Copies the systemd units into `/etc/systemd/system/` and runs `daemon-reload`.
7. **Does NOT** start the units yet — you set up `redteam.env` and `nginx.conf` first.

---

## 2. Configure secrets

```bash
mkdir -p /etc/agentforge-redteam
cp /srv/agentforge-redteam/deploy/redteam.env.template /etc/agentforge-redteam/redteam.env
chmod 600 /etc/agentforge-redteam/redteam.env
chown agentforge-redteam:agentforge-redteam /etc/agentforge-redteam/redteam.env
vim /etc/agentforge-redteam/redteam.env
```

Fill in every value the template marks as `REQUIRED`. **The web UI refuses to boot
without `WEB_UI_PASSWORD`** — that check is enforced by the systemd unit, not Python.

---

## 3. nginx + Let's Encrypt

Replace `platform.example.com` with your domain in `deploy/nginx.conf`, then:

```bash
cp /srv/agentforge-redteam/deploy/nginx.conf /etc/nginx/sites-available/agentforge-redteam
ln -sf /etc/nginx/sites-available/agentforge-redteam /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default      # remove the welcome page if present
nginx -t                                     # validate config
systemctl reload nginx

# Then issue the cert. certbot rewrites the server block to add the TLS pieces.
certbot --nginx -d platform.example.com --redirect --agree-tos -m you@example.com
```

Auto-renew is handled by certbot's own systemd timer (`certbot.timer`), which Ubuntu
enables out of the box. Verify with `systemctl list-timers | grep certbot`.

---

## 4. Start the units

```bash
systemctl enable --now agentforge-redteam-web.service
systemctl enable --now agentforge-redteam-nightly.timer

systemctl status agentforge-redteam-web.service
systemctl list-timers | grep agentforge
journalctl -u agentforge-redteam-web.service -f         # tail logs
```

The web service should be `active (running)` and listening on `127.0.0.1:8080`. nginx
proxies `https://platform.example.com/` to it.

---

## 5. Smoke test from your laptop

```bash
USER=operator PASS='<your-password>'
curl -u "$USER:$PASS" https://platform.example.com/healthz       # -> {"status":"ok"}
curl -u "$USER:$PASS" https://platform.example.com/ui            # -> HTML
```

Then open `https://platform.example.com/ui` in a browser. BasicAuth prompts on first
load.

---

## 6. (Optional) Wire GitLab CI to trigger sessions remotely

If you prefer GitLab CI's scheduler over systemd timers, the project's `.gitlab-ci.yml`
already has a `nightly_run` job stub. Configure it via the GitLab UI:

1. Project → **Settings → CI/CD → Variables**. Add `DEPLOY_SSH_PRIVATE_KEY` (file type,
   protected, masked).
2. Project → **Build → Pipeline schedules**. Add a schedule: `0 2 * * *` UTC, target
   branch `main`. The `nightly_run` job is rule-gated to only fire on schedules.
3. The droplet's `~root/.ssh/authorized_keys` must contain the corresponding public key.

The GitLab path is **redundant** with the systemd timer above. Pick one. I recommend the
systemd timer — fewer moving parts, no external dependency on GitLab being up at 02:00.

---

## Operations cheat sheet

```bash
# Live tail
journalctl -u agentforge-redteam-web.service -f
journalctl -u agentforge-redteam-nightly.service --since "2h ago"

# Trip / clear kill switch from the droplet
sudo -u agentforge-redteam env -S "$(cat /etc/agentforge-redteam/redteam.env)" \
    bash -c 'cd /srv/agentforge-redteam && uv run agentforge-redteam halt'

# Restart the web service after editing redteam.env
systemctl restart agentforge-redteam-web.service

# Roll the password without downtime
vim /etc/agentforge-redteam/redteam.env
systemctl reload-or-restart agentforge-redteam-web.service

# Back up the SQLite DB
sqlite3 /srv/agentforge-redteam/var/platform.db ".backup '/root/backup-$(date +%F).db'"

# Migrate after a deploy
cd /srv/agentforge-redteam && git pull
sudo -u agentforge-redteam uv sync --frozen
sudo -u agentforge-redteam uv run alembic upgrade head
systemctl restart agentforge-redteam-web.service
```

---

## What this deploy does NOT do

* **No high availability.** One droplet, one process, one SQLite file. The kill switch
  is the only recovery primitive. If the droplet dies, the platform is down until you
  spin up a new one and restore the SQLite file from backup.
* **No traffic encryption between nginx and uvicorn.** They're on loopback. If your
  threat model includes a malicious co-tenant on the same droplet, you have bigger
  problems.
* **No log aggregation.** Logs go to journald only. Pipe them somewhere durable (Vector,
  Loki, Logflare) if you care about retention beyond what journald keeps.
* **No outbound proxy.** The agents talk directly to Anthropic / OpenAI / GitLab from
  the droplet. If you need an egress proxy, set `HTTPS_PROXY` in `redteam.env` and
  trust your TLS chain.

---

## When you outgrow this

The migration story is short: the SQLite layer (Task 12) chose SQLAlchemy + Alembic
specifically so a swap to Postgres is one URL change and one schema-replay. The web
service is stateless apart from the SQLite engine in `db.py`; horizontal scale is a
HAProxy in front of two uvicorn workers once you've moved the DB off-droplet. None of
that is needed for the MVP.
