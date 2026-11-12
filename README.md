# GarudaShield AI Dashboard

Laravel 12 web dashboard for the GarudaShield AI FastAPI detection engine. Laravel is used as the authenticated presentation layer and calls FastAPI server to server; event detection and storage remain in the Python engine.

## Requirements

- PHP 8.2+ with cURL, OpenSSL, PDO, Mbstring, Tokenizer, XML and Ctype extensions enabled
- Composer 2
- Python FastAPI detection engine, reachable from the PHP host

## Install and run

```powershell
composer install
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
php artisan key:generate
```

Edit `.env` and set a unique dashboard password, then run:

```powershell
php artisan serve --port=8080
```

Open `http://127.0.0.1:8080` and sign in with `GARUDASHIELD_DASHBOARD_USERNAME` and `GARUDASHIELD_DASHBOARD_PASSWORD`. Using port 8080 leaves FastAPI's default port 8000 available. Choose another port if 8080 is already in use.

For a password hash, create one with `php artisan tinker` and `Hash::make('your-long-password')`, then put the resulting bcrypt string in `GARUDASHIELD_DASHBOARD_PASSWORD`. The login accepts bcrypt hashes as well as a plaintext value; a hash is recommended. Set `APP_DEBUG=false`, use HTTPS, and keep `.env` private in deployments. The dashboard has a session login and login rate limit; use your organization's SSO/reverse proxy and network restrictions for production access.

## FastAPI connection

Set the Laravel server's `.env` value:

```dotenv
GARUDASHIELD_API_URL=http://192.168.1.103:8000
```

The value is the base URL as seen by the PHP/Laravel server. If FastAPI is on a different machine, container, or VM, use its reachable private service address, for example `http://garudashield-engine:8000` or `http://10.0.0.12:8000`. Do not expose the engine publicly just to connect the dashboard. After changing `.env`, run `php artisan config:clear` if configuration is cached.

Laravel reads the URL through `config('services.garudashield.url')`, strips a trailing slash, and calls `GET /health`, `GET /api/v1/dashboard/summary`, `GET /api/v1/events?limit=50`, and `GET /api/v1/alerts`. Run `php artisan garudashield:check-api` from the Laravel host to verify connectivity and response schemas. HTTP errors, connection failures, invalid JSON, and response schema errors are logged separately in `storage/logs/laravel.log` and shown with distinct safe messages. Event ingestion and detection remain in FastAPI; a separate optional SSH log collector is documented in [collector/README.md](collector/README.md). No IP blocking or detection logic is implemented in Laravel.

## Timestamp handling

Laravel keeps its application timezone at UTC. API timestamps with `Z` or an explicit UTC offset are parsed as instants and rendered in `Asia/Jakarta` as `d M Y, H:i:s WIB`; comparisons and list ordering use the parsed instant. Timestamp strings without an offset are not silently treated as the browser's timezone or guessed as UTC. They are shown with a “zona waktu tidak diketahui” label and excluded from time-based comparisons, while retaining their API order after timestamps with known instants. Once the FastAPI database and its timestamp convention have been verified, `GARUDASHIELD_NAIVE_TIMESTAMP_TIMEZONE=UTC` (or the verified zone) can set an explicit interpretation policy. No historic API or SQLite values are rewritten by Laravel.

The SSH collector reads `/var/log/secure` syslog timestamps, which have local wall-clock time but no embedded timezone. It attaches the collector host's configured timezone, preserves that instant, and sends it to FastAPI as UTC ISO 8601 (`Z`). The original source clock can be reconstructed in the host zone. Keep the collector host timezone correct; do not infer a timezone for existing stored records based only on their display.

### Read-only time and NTP checks

On the Windows Laravel host, run PowerShell:

```powershell
Get-TimeZone
Get-Date -AsUTC -Format o
Get-Service W32Time
w32tm /query /status
w32tm /query /source
```

On each AlmaLinux VM (`192.168.1.103` FastAPI and `192.168.1.102` Ollama), run:

```bash
date --iso-8601=ns
date -u --iso-8601=ns
timedatectl status
timedatectl show -p Timezone -p NTPSynchronized -p NTP -p CanNTP
readlink -f /etc/localtime
systemctl status chronyd --no-pager
chronyc tracking
chronyc sources -v
```

These commands inspect status only. `chronyc` may be unavailable if chrony is not installed; `timedatectl` still reports the system's synchronization state. For the FastAPI SQLite database, inspect the configured database path and timestamp columns read-only before selecting a naive-time policy; do not rewrite records to “fix” their apparent timezone.

### AI alert analysis

On an alert investigation page, **Analyze with AI** sends a server-side `POST /api/v1/alerts/{id}/analyze` request to FastAPI. Laravel reads status from `GET /api/v1/alerts/{id}/analysis`; it never connects directly to Ollama. Pending/running analyses are checked every 8 seconds for up to 96 seconds, then can be refreshed manually. Completed results are presented as incident summary, facts stated by the analysis, hypotheses, and recommended actions. AI output is advisory and should be checked against the underlying records. The FastAPI engine and its configured model must be reachable for the live demo.

For a demo, start the existing FastAPI engine and its configured Ollama model, make sure the PHP host can reach `GARUDASHIELD_API_URL`, sign in, open **Security alerts**, then open an alert and click **Analyze with AI**. Wait for the status to complete or use **Refresh analysis status**. The dashboard does not create attack traffic; use the project's existing SSH simulation/collector workflow to generate an alert first.

## Pages

- Overview: eight summary values read from FastAPI (missing API values appear as an em dash).
- Security events: up to 50 API events with a basic search.
- Security alerts: API alert queue with severity and risk indicators, an evidence and context detail view, and optional AI analysis through FastAPI.

Alerts indicate a rule match and do not prove account compromise. Analysts should review source, account context, and surrounding events.

## Checks

Run `php artisan route:list` to review web routes and `php artisan test` for the Laravel suite. FastAPI must be running and contain records to validate live data and AI analysis; tests mock the API and do not seed demonstration security data.
