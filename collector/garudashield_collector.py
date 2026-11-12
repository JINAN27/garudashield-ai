#!/usr/bin/env python3
"""Incrementally collect sshd authentication events and spool them to FastAPI."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Optional
from zoneinfo import ZoneInfo


LOG = logging.getLogger("garudashield_collector")
LOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
FAILED_RE = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+"
    r"(?:(?:invalid|illegal)\s+user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)(?:\s|$)", re.IGNORECASE
)
INVALID_USER_RE = re.compile(
    r"Invalid user\s+(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+"
    r"port\s+(?P<port>\d+)(?:\s|$)", re.IGNORECASE
)
ACCEPTED_RE = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)(?:\s|$)", re.IGNORECASE
)
MAX_RECENT_KEYS = 4096
MAX_BACKOFF_SECONDS = 60


def system_timezone() -> tzinfo:
    """Read the collector host's configured zone for syslog timestamps without offsets."""
    configured = os.environ.get("TZ", "").strip()
    if configured:
        try:
            return ZoneInfo(configured.lstrip(":"))
        except (KeyError, ValueError):
            pass

    localtime = Path("/etc/localtime")
    try:
        resolved = localtime.resolve()
        parts = resolved.parts
        zoneinfo_index = parts.index("zoneinfo")
        return ZoneInfo("/".join(parts[zoneinfo_index + 1 :]))
    except (OSError, ValueError, KeyError):
        try:
            with localtime.open("rb") as zone_file:
                return ZoneInfo.from_file(zone_file)
        except OSError:
            # Portable fallback for development platforms without /etc/localtime.
            return datetime.now().astimezone().tzinfo or ZoneInfo("UTC")


@dataclass(frozen=True)
class ParsedEvent:
    payload: dict[str, str]
    dedupe_key: str


class EventParser:
    """Parse only sshd authentication records; never retain the raw log line."""

    def __init__(self, source_timezone: Optional[tzinfo] = None):
        self.source_timezone = source_timezone or system_timezone()

    def parse(self, line: str, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
        record = LOG_RE.match(line.rstrip("\r\n"))
        if not record:
            return None

        message = record.group("message")
        match = FAILED_RE.search(message)
        event_type = "ssh_login_failed"
        if not match:
            match = INVALID_USER_RE.search(message)
        if not match:
            match = ACCEPTED_RE.search(message)
            event_type = "ssh_login_success"
        if not match:
            return None

        username = match.group("username")
        if not username or len(username) > 128 or any(ord(char) < 32 for char in username):
            return None
        try:
            source_ip = str(ipaddress.ip_address(match.group("ip")))
        except ValueError:
            return None

        timestamp = self._timestamp(record.group("month"), record.group("day"), record.group("clock"), now, self.source_timezone)
        if timestamp is None:
            return None

        payload = {
            "event_type": event_type,
            "source_ip": source_ip,
            "username": username,
            "timestamp": timestamp,
        }
        # Port is local-only: it distinguishes separate attempts while collapsing
        # sshd's paired "Invalid user" and "Failed password" lines for one attempt.
        fingerprint = "|".join((event_type, timestamp, source_ip, username, match.group("port")))
        return ParsedEvent(payload, hashlib.sha256(fingerprint.encode("utf-8")).hexdigest())

    @staticmethod
    def _timestamp(month: str, day: str, clock: str, now: Optional[datetime], source_timezone: tzinfo) -> Optional[str]:
        if now is None:
            current = datetime.now(source_timezone)
        elif now.tzinfo is None:
            current = now.replace(tzinfo=source_timezone)
        else:
            current = now.astimezone(source_timezone)
        try:
            parsed = datetime.strptime(f"{current.year} {month} {day} {clock}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        # /var/log/secure uses local wall time without a timezone. Attach the
        # collector host's configured zone while retaining the logged clock time.
        parsed = parsed.replace(tzinfo=source_timezone)
        if parsed - current > timedelta(days=1):
            parsed = parsed.replace(year=parsed.year - 1)
        # Normalize the parsed instant to UTC before posting. Its source wall
        # clock remains recoverable by converting this aware value back to the
        # collector host zone; no timezone-naive value crosses the API boundary.
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class StateStore:
    """Atomic persistent cursor and outbox. A line is checkpointed with its event."""

    def __init__(self, state_dir: Path):
        self.directory = state_dir
        self.path = state_dir / "state.json"
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(state_dir, 0o700)
        except OSError:
            pass
        if self.path.exists():
            try:
                self.state = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Cannot read collector state safely: {exc.__class__.__name__}") from exc
            if not self._valid(self.state):
                raise RuntimeError("Collector state has an unsupported or invalid format; refusing to reset it")
        else:
            self.state = {"version": 1, "cursor": None, "pending": [], "recent": []}
            self.save()

    @staticmethod
    def _valid(state: Any) -> bool:
        return (
            isinstance(state, dict)
            and state.get("version") == 1
            and (state.get("cursor") is None or isinstance(state.get("cursor"), dict))
            and isinstance(state.get("pending"), list)
            and isinstance(state.get("recent"), list)
        )

    def save(self) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=".state-", dir=self.directory)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            else:
                os.chmod(temp_name, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.state, handle, separators=(",", ":"), ensure_ascii=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            if os.name != "nt":
                dir_fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 5.0, opener: Any = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        parts = urllib.parse.urlsplit(self.base_url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or parts.path not in ("", "/")
        ):
            raise ValueError("GARUDASHIELD_API_URL must be an HTTP(S) origin without credentials or a path")
        self.endpoint = self.base_url + "/api/v1/events"
        self.opener = opener or urllib.request.build_opener(NoRedirectHandler())

    def post_event(self, payload: dict[str, str]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise urllib.error.HTTPError(self.endpoint, response.status, "unexpected HTTP status", response.headers, None)


class Collector:
    def __init__(
        self,
        log_file: Path,
        state_dir: Path,
        api_client: ApiClient,
        dry_run: bool = True,
        start_at_end: bool = True,
        clock: Callable[[], float] = time.time,
        parser: Optional[EventParser] = None,
    ):
        self.log_file = log_file
        self.store = StateStore(state_dir)
        self.api_client = api_client
        self.dry_run = dry_run
        self.start_at_end = start_at_end
        self.clock = clock
        self.parser = parser or EventParser()
        self._last_file_error_at: Optional[float] = None
        self.last_read_error = False

    def read_available(self) -> int:
        self.last_read_error = False
        try:
            active_stat = self.log_file.stat()
        except OSError as exc:
            self.last_read_error = True
            self._log_file_error("Cannot read configured auth log %s (%s)", self.log_file, exc.__class__.__name__)
            return 0
        if not self.log_file.is_file():
            self.last_read_error = True
            self._log_file_error("Configured auth log is not a regular file: %s", self.log_file)
            return 0

        cursor = self.store.state["cursor"]
        if cursor is None:
            offset = active_stat.st_size if self.start_at_end else 0
            self.store.state["cursor"] = self._cursor(active_stat, offset)
            self.store.save()
            LOG.info("Initialized auth-log cursor at %s (existing content skipped=%s)", offset, self.start_at_end)
            if self.start_at_end:
                return 0
            cursor = self.store.state["cursor"]

        if self._same_file(cursor, active_stat):
            if active_stat.st_size < cursor["offset"]:
                LOG.error("Auth log was truncated; resuming at start of the truncated file")
                cursor["offset"] = 0
                self.store.save()
            return self._read_file(self.log_file, cursor)

        old_path = self._find_inode(cursor)
        if old_path is None:
            self.last_read_error = True
            self._log_file_error("Auth log rotated but prior inode %s is unavailable; cursor was not advanced", cursor.get("inode"))
            return 0
        try:
            old_stat = old_path.stat()
        except OSError as exc:
            self.last_read_error = True
            self._log_file_error("Cannot inspect rotated auth log %s (%s)", old_path, exc.__class__.__name__)
            return 0
        processed = self._read_file(old_path, cursor, rotated=True)
        latest_offset = self.store.state["cursor"]["offset"]
        try:
            latest_size = old_path.stat().st_size
        except OSError:
            latest_size = latest_offset
        if latest_offset >= latest_size:
            self.store.state["cursor"] = self._cursor(active_stat, 0)
            self.store.save()
            LOG.info("Drained rotated auth log; switched cursor to current inode")
        return processed

    def _read_file(self, path: Path, cursor: dict[str, int], rotated: bool = False) -> int:
        processed = 0
        try:
            with path.open("rb") as handle:
                actual = os.fstat(handle.fileno())
                if not self._same_file(cursor, actual):
                    self.last_read_error = True
                    LOG.error("Auth log changed while opening %s; will retry", path)
                    return 0
                handle.seek(cursor["offset"])
                while True:
                    start = handle.tell()
                    raw = handle.readline()
                    if not raw:
                        break
                    end = handle.tell()
                    if not raw.endswith(b"\n") and not rotated:
                        # Keep a partial record at the cursor until its newline arrives.
                        break
                    line = raw.decode("utf-8", errors="replace")
                    parsed = self.parser.parse(line)
                    cursor = self._cursor(actual, end)
                    queued = self._commit_line(cursor, parsed)
                    if parsed and queued:
                        processed += 1
                        if self.dry_run:
                            LOG.info("DRY RUN parsed %s id=%s", parsed.payload["event_type"], parsed.dedupe_key[:12])
                        else:
                            LOG.info("Queued %s event id=%s", parsed.payload["event_type"], parsed.dedupe_key[:12])
                    elif parsed:
                        LOG.debug("Coalesced duplicate sshd authentication record id=%s", parsed.dedupe_key[:12])
                    elif LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug("Skipped non-authentication or malformed sshd log line at offset %s", start)
                if self.store.state["cursor"] != cursor:
                    self.store.state["cursor"] = cursor
                    self.store.save()
        except OSError as exc:
            self.last_read_error = True
            self._log_file_error("Cannot read auth log %s (%s)", path, exc.__class__.__name__)
        return processed

    def _log_file_error(self, message: str, *args: Any) -> None:
        now = self.clock()
        if self._last_file_error_at is None or now - self._last_file_error_at >= 60:
            LOG.error(message, *args)
            self._last_file_error_at = now

    def _commit_line(self, cursor: dict[str, int], parsed: Optional[ParsedEvent]) -> bool:
        if parsed:
            is_new = parsed.dedupe_key not in self.store.state["recent"]
            if is_new:
                item_id = parsed.dedupe_key
                self.store.state["pending"].append({
                    "id": item_id,
                    "event": parsed.payload,
                    "attempts": 0,
                    "next_attempt": 0,
                })
                self.store.state["recent"].append(parsed.dedupe_key)
                self.store.state["recent"] = self.store.state["recent"][-MAX_RECENT_KEYS:]
            self.store.state["cursor"] = cursor
            self.store.save()
            return is_new
        self.store.state["cursor"] = cursor
        return False

    def deliver_one(self) -> bool:
        if self.dry_run or not self.store.state["pending"]:
            return False
        item = self.store.state["pending"][0]
        now = self.clock()
        if item["next_attempt"] > now:
            return False
        try:
            self.api_client.post_event(item["event"])
        except urllib.error.HTTPError as exc:
            self._schedule_retry(item, f"HTTP {exc.code}")
            return False
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._schedule_retry(item, exc.__class__.__name__)
            return False
        except Exception as exc:
            self._schedule_retry(item, exc.__class__.__name__)
            return False

        self.store.state["pending"].pop(0)
        self.store.save()
        LOG.info("Event accepted by Detection Engine id=%s", item["id"][:12])
        return True

    def _schedule_retry(self, item: dict[str, Any], reason: str) -> None:
        item["attempts"] += 1
        delay = min(2 ** (item["attempts"] - 1), MAX_BACKOFF_SECONDS)
        item["next_attempt"] = self.clock() + delay
        self.store.save()
        LOG.warning("Event delivery failed (%s); retry in %ss id=%s", reason, delay, item["id"][:12])

    def run_once(self) -> int:
        count = self.read_available()
        while self.deliver_one():
            pass
        return count

    @staticmethod
    def _cursor(stat: os.stat_result, offset: int) -> dict[str, int]:
        return {"device": int(stat.st_dev), "inode": int(stat.st_ino), "offset": int(offset)}

    @staticmethod
    def _same_file(cursor: dict[str, int], stat: os.stat_result) -> bool:
        return cursor["device"] == stat.st_dev and cursor["inode"] == stat.st_ino

    def _find_inode(self, cursor: dict[str, int]) -> Optional[Path]:
        for candidate in self.log_file.parent.glob(self.log_file.name + "*"):
            try:
                stat = candidate.stat()
            except OSError:
                continue
            if stat.st_dev == cursor["device"] and stat.st_ino == cursor["inode"] and candidate.is_file():
                return candidate
        return None


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Parse and persist events without posting to FastAPI")
    parser.add_argument("--once", action="store_true", help="Read available log records once and exit")
    parser.add_argument("--from-start", action="store_true", help="Read existing file from byte zero (testing only)")
    parser.add_argument("--log-file", type=Path, help="Override GARUDASHIELD_LOG_FILE (useful for fixture tests)")
    parser.add_argument("--state-dir", type=Path, help="Override GARUDASHIELD_STATE_DIR (use a temporary directory for tests)")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=os.environ.get("GARUDASHIELD_LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    api_url = os.environ.get("GARUDASHIELD_API_URL", "http://127.0.0.1:8000")
    log_file = args.log_file or Path(os.environ.get("GARUDASHIELD_LOG_FILE", "/var/log/secure"))
    state_dir = args.state_dir or Path(os.environ.get("GARUDASHIELD_STATE_DIR", "/var/lib/garudashield-collector"))
    dry_run = args.dry_run or env_bool("GARUDASHIELD_DRY_RUN", True)

    try:
        collector = Collector(
            log_file=log_file,
            state_dir=state_dir,
            api_client=ApiClient(api_url, timeout=float(os.environ.get("GARUDASHIELD_HTTP_TIMEOUT", "5"))),
            dry_run=dry_run,
            start_at_end=not args.from_start,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        LOG.error("Collector cannot start (%s): %s", exc.__class__.__name__, exc)
        return 2

    LOG.info("Collector started; dry_run=%s log_file=%s", dry_run, log_file)
    if args.once:
        collector.run_once()
        return 1 if collector.last_read_error else 0

    stopping = False

    def stop(signum: int, frame: Any) -> None:
        nonlocal stopping
        stopping = True
        LOG.info("Received signal %s; stopping", signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        poll_seconds = max(0.2, float(os.environ.get("GARUDASHIELD_POLL_SECONDS", "1")))
        idle_warning_seconds = max(30.0, float(os.environ.get("GARUDASHIELD_IDLE_WARN_SECONDS", "300")))
    except ValueError:
        LOG.error("GARUDASHIELD_POLL_SECONDS and GARUDASHIELD_IDLE_WARN_SECONDS must be numeric")
        return 2
    last_signature = None
    last_growth = time.monotonic()
    last_idle_warning = 0.0
    while not stopping:
        collector.run_once()
        try:
            log_stat = log_file.stat()
            signature = (log_stat.st_dev, log_stat.st_ino, log_stat.st_size)
        except OSError:
            signature = None
        now = time.monotonic()
        if signature is not None and signature != last_signature:
            last_signature = signature
            last_growth = now
            last_idle_warning = 0.0
        elif signature is not None and now - last_growth >= idle_warning_seconds and now - last_idle_warning >= idle_warning_seconds:
            LOG.warning("No new bytes observed in %s for at least %.0f seconds; verify sshd and log routing", log_file, idle_warning_seconds)
            last_idle_warning = now
        time.sleep(poll_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
