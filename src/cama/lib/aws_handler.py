from __future__ import annotations

import json
import os
import shutil
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional


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


def fetch_and_format_aws_logs(days: int, client: Optional[Any] = None) -> str:
    """Fetch, group, and write AWS CloudTrail events by eventName.

    Authentication is handled by standard AWS environment variables:
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_DEFAULT_REGION.

    Steps:
    - Fetch CloudTrail events for the last `days` days using lookup_events with pagination.
    - Group raw events by EventName.
    - Write one JSON file per unique event name into a unique .cache/run_* directory.

    Args:
        days: Number of days back from now to include.
        client: Optional pre-configured boto3 CloudTrail client.

    Returns:
        Absolute path to the created run subdirectory containing JSON files.

    Raises:
        ValueError: If inputs or environment configuration are invalid.
        RuntimeError: For other operational errors during fetch/write.
    """
    if not isinstance(days, int) or days <= 0:
        raise ValueError("'days' must be a positive integer")

    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("boto3 is required for AWS ingestion") from exc

    # Ensure region is available when creating the client automatically
    if client is None:
        region = os.getenv("AWS_DEFAULT_REGION")
        if not region:
            raise ValueError("AWS_DEFAULT_REGION environment variable is not set")
        try:
            client = boto3.client("cloudtrail", region_name=region)
        except Exception as exc:
            raise RuntimeError("Failed to create boto3 CloudTrail client") from exc

    now = _to_datetime(datetime.now(timezone.utc))
    start = now - timedelta(days=days)

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
