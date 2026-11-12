# GarudaShield SSH log collector

This is a separate, standard-library-only Python service that tails AlmaLinux `/var/log/secure` and posts only the documented event fields to the existing FastAPI engine. It does not change Laravel, FastAPI, or the engine's SQLite database. The supplied systemd unit is **not enabled or started** by this implementation.

## API contract audited

The Laravel workspace contains no FastAPI source. The running engine's read-only `/openapi.json` was inspected at `192.168.1.103:8000`. Its `POST /api/v1/events` request schema is `SecurityEvent`:

- Required: `event_type`, `source_ip`, `username`
- Optional nullable ISO date-time: `timestamp`
- Allowed event types: `ssh_login_failed`, `ssh_login_success`
- OpenAPI documents HTTP 200 on success and HTTP 422 for validation errors.

The collector sends exactly these fields, with no raw log message, local fingerprint, or source port. SSH rules are described in the dashboard brief (5 failures/5 minutes and success after 3 failures/10 minutes for a matching IP/username); their implementation and database write semantics are not exposed in the OpenAPI schema and were not independently audited because the engine source is not in this repository. No event was POSTed to the live engine during this work.

Delivery is at least once. A local SHA-256 fingerprint prevents replay on restart and coalesces sshd's paired `Invalid user` and `Failed password` lines for the same timestamp, IP, username, and source port. The API contract has no event ID or idempotency field, so a process/network failure after the server stores an event but before its 2xx response is received can cause one duplicate on retry. The collector never discards a queued event on API errors.

## Test parser and dry-run

Requires Python 3.9+; no pip install is needed. On the VM, the detection engine's `/opt/garudashield/.venv/bin/python` is used by systemd so it follows the already installed runtime. From this directory during local development:

```bash
python3 -m unittest -v test_collector.py
GARUDASHIELD_DRY_RUN=true python3 garudashield_collector.py \
  --dry-run --once --from-start \
  --log-file tests/fixtures/secure-sample.log \
  --state-dir /tmp/garudashield-collector-dryrun
```

The synthetic sample should report one `ssh_login_failed` and one `ssh_login_success` parse, and makes no HTTP request. The dry-run still persists its outbox; use a fresh temporary state directory for repeatable sample checks. The service's normal first start records the current end of the log and skips older content. `--from-start` is a fixture/testing option and should not be used against the production log.

## Deploy on the AlmaLinux VM

Copy this `collector/` directory to `/opt/garudashield-collector/`, then create the unprivileged account and protected state directory:

```bash
sudo useradd --system --home-dir /var/lib/garudashield-collector --shell /sbin/nologin garudashield-collector
sudo install -d -o garudashield-collector -g garudashield-collector -m 0700 /var/lib/garudashield-collector
sudo install -m 0644 systemd/garudashield-collector.service /etc/systemd/system/garudashield-collector.service
sudo install -o root -g garudashield-collector -m 0640 garudashield-collector.env.example /etc/garudashield-collector.env
```

The example environment points at `http://127.0.0.1:8000` and sets `GARUDASHIELD_DRY_RUN=true`. Keep dry-run enabled during review. The service account needs read access to `/var/log/secure`, but the file must not be made world-readable. Check the current owner, mode, ACL, and logrotate rule first:

```bash
sudo stat -c '%A %U:%G %n' /var/log/secure
sudo getfacl /var/log/secure
sudo grep -R -n '/var/log/secure' /etc/logrotate.conf /etc/logrotate.d
```

One least-privilege option is a per-file ACL for the existing file, then configure the matching logrotate stanza to create rotated active logs with group `garudashield-collector` and mode `0640` (rather than world-readable permissions):

```bash
sudo setfacl -m u:garudashield-collector:r /var/log/secure
```

Validate the ACL and newly created file after a controlled log rotation before relying on continuous collection. Do not enable the collector if it logs permission or rotation errors. If local log policy uses a different owner/group or rotation tool, adapt that policy instead of broadening permissions.

Install, reload systemd, and run only a sample dry-run first:

```bash
sudo systemctl daemon-reload
sudo install -d -o garudashield-collector -g garudashield-collector -m 0700 /var/lib/garudashield-collector/dryrun-sample
sudo -u garudashield-collector env GARUDASHIELD_DRY_RUN=true \
  GARUDASHIELD_API_URL=http://127.0.0.1:8000 \
  GARUDASHIELD_LOG_FILE=/opt/garudashield-collector/tests/fixtures/secure-sample.log \
  GARUDASHIELD_STATE_DIR=/var/lib/garudashield-collector/dryrun-sample \
  /opt/garudashield/.venv/bin/python /opt/garudashield-collector/garudashield_collector.py --dry-run --once --from-start
```

Check the sample output and `journalctl` before deciding whether to switch the environment file to `GARUDASHIELD_DRY_RUN=false`. This project does not enable or start the unit automatically. Only after a human has verified dry-run parsing and is ready for live events, start it manually; enable at boot only after that review:

```bash
sudo systemctl start garudashield-collector.service
sudo journalctl -u garudashield-collector.service -f
sudo systemctl enable garudashield-collector.service
```

To run the collector interactively after configuring the environment file:

```bash
set -a
source /etc/garudashield-collector.env
set +a
/opt/garudashield/.venv/bin/python /opt/garudashield-collector/garudashield_collector.py --dry-run
```

## Operations and limits

- Checkpoint and outbox are stored in `/var/lib/garudashield-collector/state.json`, with directory mode 0700 and state file mode 0600. Each event is atomically added to the outbox with its cursor before delivery.
- On network/HTTP failure, oldest event remains queued and retries use exponential delays from 1 to 60 seconds. A malformed state file causes startup to stop instead of resetting the cursor.
- On inode rotation, the collector drains the old inode if it remains available under a matching rotated filename, then tails the new active file. If the prior inode is missing, it logs an error and does not silently advance. On detected truncation, it logs an error and restarts at byte zero of the truncated file; bytes already removed by logrotate cannot be recovered.
- `/var/log/secure` timestamps omit timezone and year. The collector preserves the logged month/day/clock fields, applies the host's configured timezone (from `TZ` or `/etc/localtime`), and sends the resulting instant to FastAPI as UTC ISO 8601 (`Z`). Only sshd authentication patterns with a valid IP, username (up to 128 characters), and timestamp are sent. Verify the VM timezone and NTP state before relying on these timestamps for incident ordering; historical database values are not rewritten.
- HTTP redirects are not followed; the configured API origin is the only target. Timeout defaults to 5 seconds. No shell commands are run from log content, no IP blocking is performed, and no external Python packages are used.
- If `/var/log/secure` remains unchanged for 300 seconds, the process writes an actionable warning to the journal. Missing or unreadable log files also generate rate-limited errors. SELinux stays enabled; if access is denied despite the Unix ACL, inspect AVC records and create an appropriately scoped policy rather than disabling enforcement.
- An API response lost after database commit can be retried because the current event schema does not offer server-side idempotency. This at-least-once limitation cannot be removed in the collector without a compatible API change.
