from __future__ import annotations

import json
import os
import shutil
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Tuple


def _ensure_cache_run_dir() -> Path:
    """Create and return a unique run directory under the project-level .cache.

    Also purges any existing contents in .cache before creating the new run
    directory, ensuring previous logs are deleted on each ingestion run.

    The path will look like <project_root>/.cache/run_YYYYMMDD_HHMMSS
    where project_root is inferred from this file's location.
    """
    project_root = Path(__file__).resolve().parents[3]
    cache_root = project_root / ".cache"
    cache_root.mkdir(parents=True, exist_ok=True)

    # Purge previous contents inside .cache
    for child in cache_root.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass

    timestamp = datetime.now(timezone.utc).strftime("run_%Y%m%d_%H%M%S")
    run_dir = cache_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _sanitize_filename(name: str) -> str:
    """Sanitize a string to be safe for filenames."""
    safe = name.strip().replace(" ", "_")
    for ch in ["/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."]:
        safe = safe.replace(ch, "_")
    return safe.lower() or "unknown"


def _to_datetime(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_event_time(value: Any) -> Optional[datetime]:
    """Parse event time from various CloudTrail representations to UTC datetime.

    Accepts ISO8601 strings with or without 'Z', or datetime objects. Returns None if unknown.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return _to_datetime(value)
    if isinstance(value, str):
        s = value.strip()
        # Normalize 'Z' suffix
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return _to_datetime(datetime.fromisoformat(s))
        except Exception:
            # Try common AWS format fallback: 2023-07-10T11:45:00Z without timezone parsing
            try:
                return _to_datetime(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
            except Exception:
                return None
    return None


def _iter_local_cloudtrail_events(directory: Path) -> Iterable[Dict[str, Any]]:
    """Yield CloudTrail events from JSON files under the given directory (non-recursive).

    Supports files with top-level 'Records' (standard CloudTrail logs) or 'Events' (lookup-style),
    as well as a raw list of event dicts.
    """
    if not directory.exists() or not directory.is_dir():
        return []

    for p in sorted(directory.iterdir()):
        if not (p.is_file() and p.suffix.lower() == ".json"):
            continue
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        if isinstance(data, dict):
            if isinstance(data.get("Records"), list):
                for ev in data["Records"]:
                    if isinstance(ev, dict):
                        yield ev
            elif isinstance(data.get("Events"), list):
                for ev in data["Events"]:
                    if isinstance(ev, dict):
                        yield ev
            else:
                # Sometimes CloudTrail export wraps in another key; attempt to find list of dicts
                for v in data.values():
                    if isinstance(v, list) and v and isinstance(v[0], dict):
                        for ev in v:
                            yield ev
                        break
        elif isinstance(data, list):
            for ev in data:
                if isinstance(ev, dict):
                    yield ev


def _group_and_write(events: Iterable[Dict[str, Any]], time_bounds: Optional[Tuple[datetime, datetime]] = None) -> str:
    grouped: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)

    for ev in events:
        event_name = (
            ev.get("eventName")
            or ev.get("EventName")
            or "unknown_event"
        )
        # Optional time filtering when bounds provided
        if time_bounds is not None:
            start, end = time_bounds
            evt_time = _parse_event_time(ev.get("eventTime") or ev.get("EventTime"))
            if evt_time is not None and not (start <= evt_time <= end):
                continue
        grouped[event_name].append(ev)

    run_dir = _ensure_cache_run_dir()
    for event_name, logs in grouped.items():
        filename = f"aws_{_sanitize_filename(event_name)}.json"
        out_path = run_dir / filename
        try:
            with out_path.open("w", encoding="utf-8") as f:
                json.dump(logs, f, ensure_ascii=False, indent=2, default=str)
        except OSError as exc:
            raise RuntimeError(f"Failed to write file: {out_path}") from exc

    return str(run_dir.resolve())


def fetch_and_format_aws_logs(days: int, client: Optional[Any] = None) -> str:
    """Fetch, group, and write AWS CloudTrail events by eventName.

    Two modes are supported:
    1) Local directory mode (no credentials): if environment variable 'AWS_CLOUDTRAIL_DIR' is set
       to a directory path containing CloudTrail JSON files, those files are parsed and grouped.
    2) API mode (credentials): uses boto3 CloudTrail lookup_events with pagination.

    Steps:
    - Build a time window [now-days, now].
    - Collect events from the selected mode.
    - Group raw events by EventName/eventName.
    - Write one JSON file per unique event into a unique .cache/run_* directory.

    Args:
        days: Number of days back from now to include.
        client: Optional pre-configured boto3 CloudTrail client.

    Returns:
        Absolute path to the created run subdirectory containing JSON files.

    Raises:
        ValueError: If inputs or environment configuration are invalid.
        RuntimeError: For operational errors during fetch/write.
    """
    if not isinstance(days, int) or days <= 0:
        raise ValueError("'days' must be a positive integer")

    now = _to_datetime(datetime.now(timezone.utc))
    start = now - timedelta(days=days)

    # Prefer local directory mode when configured (timeframe is ignored for local files)
    local_dir_env = os.getenv("AWS_CLOUDTRAIL_DIR") or os.getenv("CLOUDTRAIL_DIR")
    if local_dir_env:
        directory = Path(local_dir_env).expanduser().resolve()
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Provided AWS_CLOUDTRAIL_DIR is not a directory: {directory}")
        events = _iter_local_cloudtrail_events(directory)
        # Do not filter by time for local directory mode
        return _group_and_write(events, time_bounds=None)

    # Fallback to API mode via boto3
    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("boto3 is required for AWS ingestion when AWS_CLOUDTRAIL_DIR is not set") from exc

    # Ensure region is available when creating the client automatically
    if client is None:
        region = os.getenv("AWS_DEFAULT_REGION")
        if not region:
            raise ValueError("AWS_DEFAULT_REGION environment variable is not set")
        try:
            client = boto3.client("cloudtrail", region_name=region)
        except Exception as exc:
            raise RuntimeError("Failed to create boto3 CloudTrail client") from exc

    grouped: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)

    try:
        params: Dict[str, Any] = {
            "StartTime": start,
            "EndTime": now,
        }
        next_token: Optional[str] = None
        while True:
            if next_token:
                params["NextToken"] = next_token
            response = client.lookup_events(**params)  # type: ignore[arg-type]
            events: Iterable[Dict[str, Any]] = response.get("Events", [])
            for ev in events:
                event_name = ev.get("EventName") or "unknown_event"
                grouped[event_name].append(ev)
            next_token = response.get("NextToken")
            if not next_token:
                break

        run_dir = _ensure_cache_run_dir()
        for event_name, logs in grouped.items():
            filename = f"aws_{_sanitize_filename(event_name)}.json"
            out_path = run_dir / filename
            try:
                with out_path.open("w", encoding="utf-8") as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2, default=str)
            except OSError as exc:
                raise RuntimeError(f"Failed to write file: {out_path}") from exc

        return str(run_dir.resolve())

    except (BotoCoreError, ClientError, ValueError):
        raise
    except Exception as exc:
        raise RuntimeError(f"Unexpected error during AWS log ingestion: {exc}") from exc
