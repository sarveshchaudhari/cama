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

    # Purge previous contents inside .cache (files and directories)
    for child in cache_root.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            # Best-effort cleanup; continue on errors
            pass

    timestamp = datetime.now(timezone.utc).strftime("run_%Y%m%d_%H%M%S")
    run_dir = cache_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _sanitize_filename(name: str) -> str:
    """Sanitize a string to be safe for filenames.

    Replaces problematic characters with underscores and lowers the case.
    """
    safe = name.strip().replace(" ", "_")
    for ch in ["/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."]:
        safe = safe.replace(ch, "_")
    return safe.lower() or "unknown"


def _to_iso_z(dt: datetime) -> str:
    """Return RFC3339/ISO8601 UTC string with trailing 'Z'."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _entry_to_dict(entry: Any) -> Dict[str, Any]:
    """Return the raw API representation for a google.cloud.logging entry.

    Falls back gracefully if to_api_repr is unavailable.
    """
    try:
        if hasattr(entry, "to_api_repr"):
            return entry.to_api_repr()  # type: ignore[no-any-return]
        # Fallback: try common attributes
        payload = getattr(entry, "payload", {})
        return {"payload": payload}
    except Exception:
        return {}


def fetch_and_format_gcp_logs(days: int, client: Optional[Any] = None) -> str:
    """Fetch, group, and write GCP Cloud Audit logs by methodName.

    Authentication is performed using the GOOGLE_APPLICATION_CREDENTIALS_JSON
    environment variable which must contain a full service account JSON key.

    Steps:
    - Fetch all cloudaudit.googleapis.com logs for the last `days` days.
    - Group raw entries by protoPayload.methodName.
    - Write one JSON file per unique method into a unique .cache/run_* directory.

    Args:
        days: Number of days back from now to include.
        client: Optional pre-configured google.cloud.logging.Client instance.

    Returns:
        Absolute path to the created run subdirectory containing JSON files.

    Raises:
        ValueError: If authentication configuration is missing or invalid.
        RuntimeError: For other operational errors during fetch/write.
    """
    if not isinstance(days, int) or days <= 0:
        raise ValueError("'days' must be a positive integer")

    try:
        # Lazy import to avoid hard dependency at module import time
        from google.cloud import logging as gcp_logging  # type: ignore
        from google.oauth2 import service_account  # type: ignore
        from google.api_core.exceptions import GoogleAPICallError  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency missing in some environments
        raise RuntimeError(
            "google-cloud-logging and google-auth are required for GCP ingestion"
        ) from exc

    try:
        if client is None:
            key_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
            if not key_json:
                raise ValueError(
                    "GOOGLE_APPLICATION_CREDENTIALS_JSON environment variable is not set"
                )
            try:
                info = json.loads(key_json)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "GOOGLE_APPLICATION_CREDENTIALS_JSON does not contain valid JSON"
                ) from exc

            credentials = service_account.Credentials.from_service_account_info(info)
            project_id = info.get("project_id")
            if not project_id:
                # Project can be inferred from credentials in many cases, but we enforce presence
                raise ValueError("Service account JSON must include 'project_id'")
            client = gcp_logging.Client(project=project_id, credentials=credentials)

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)
        # Advanced Logs filter: match any Cloud Audit log and time window
        logs_filter = (
            f'logName:"cloudaudit.googleapis.com" AND timestamp>="{_to_iso_z(start)}" '
            f'AND timestamp<="{_to_iso_z(now)}"'
        )

        entries_iter: Iterable[Any] = client.list_entries(filter_=logs_filter)

        grouped: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
        for entry in entries_iter:
            raw = _entry_to_dict(entry)
            # Prefer protoPayload.methodName from raw API payload
            method_name = (
                raw.get("protoPayload", {}).get("methodName")
                or raw.get("jsonPayload", {}).get("methodName")
                or "unknown_method"
            )
            grouped[method_name].append(raw)

        run_dir = _ensure_cache_run_dir()

        # Write one file per method
        for method, logs in grouped.items():
            filename = f"gcp_{_sanitize_filename(method)}.json"
            out_path = run_dir / filename
            try:
                with out_path.open("w", encoding="utf-8") as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2)
            except OSError as exc:
                raise RuntimeError(f"Failed to write file: {out_path}") from exc

        return str(run_dir.resolve())

    except (GoogleAPICallError, ValueError) as known_exc:
        # Re-raise known and meaningful exceptions
        raise
    except Exception as exc:
        raise RuntimeError(f"Unexpected error during GCP log ingestion: {exc}") from exc
