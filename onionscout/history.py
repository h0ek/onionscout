from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from .findings import make_json_safe


def default_history_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".local" / "share"
    return root / "onionscout" / "onionscout.db"


def target_key(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.hostname:
        return target.strip().lower()
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        port = 0
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{port}"


def history_path(path: Optional[str] = None) -> Path:
    return Path(path).expanduser() if path else default_history_path()


def _connect(path: Optional[str] = None) -> sqlite3.Connection:
    db_path = history_path(path)
    parent_existed = db_path.parent.exists()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if path is None or not parent_existed:
        try:
            os.chmod(db_path.parent, 0o700)
        except OSError:
            pass
    old_umask = os.umask(0o077)
    try:
        conn = sqlite3.connect(db_path)
    finally:
        os.umask(old_umask)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "target_key TEXT NOT NULL,"
        "target TEXT NOT NULL,"
        "scanned_at TEXT NOT NULL,"
        "version TEXT NOT NULL,"
        "summary_json TEXT NOT NULL,"
        "payload_json TEXT NOT NULL"
        ")"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_key, id DESC)")
    conn.commit()
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass
    return conn


def save_scan(payload: dict[str, Any], path: Optional[str] = None) -> int:
    target = str(payload.get("target") or "")
    version = str(payload.get("version") or "unknown")
    scanned_at = datetime.now(timezone.utc).isoformat()
    summary = make_json_safe(payload.get("summary") or {})
    safe_payload = make_json_safe(payload)
    safe_payload.pop("diff", None)
    with _connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO scans(target_key, target, scanned_at, version, summary_json, payload_json) VALUES(?,?,?,?,?,?)",
            (
                target_key(target),
                target,
                scanned_at,
                version,
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
                json.dumps(safe_payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_scans(target: str, path: Optional[str] = None, limit: int = 10) -> list[dict[str, Any]]:
    if not history_path(path).exists():
        return []
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT id, target, scanned_at, version, summary_json FROM scans WHERE target_key=? ORDER BY id DESC LIMIT ?",
            (target_key(target), max(1, limit)),
        ).fetchall()
    out = []
    for row in rows:
        out.append(
            {
                "id": int(row["id"]),
                "target": row["target"],
                "scanned_at": row["scanned_at"],
                "version": row["version"],
                "summary": json.loads(row["summary_json"]),
            }
        )
    return out


def latest_scan(target: str, path: Optional[str] = None) -> Optional[dict[str, Any]]:
    if not history_path(path).exists():
        return None
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT id, scanned_at, payload_json FROM scans WHERE target_key=? ORDER BY id DESC LIMIT 1",
            (target_key(target),),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "scanned_at": row["scanned_at"],
        "payload": json.loads(row["payload_json"]),
    }


def _active_findings(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for item in payload.get("results") or []:
        if str(item.get("status") or "").lower() not in {"warn", "fail"}:
            continue
        name = str(item.get("name") or "unknown")
        out[name] = {
            "name": name,
            "status": item.get("status"),
            "risk": item.get("risk"),
            "finding_type": item.get("finding_type"),
            "group": item.get("group"),
            "evidence": make_json_safe(item.get("evidence")),
        }
    return out


def _fingerprint(item: dict[str, Any]) -> str:
    return json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _check_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("name") or "unknown"): item for item in payload.get("results") or []}


def diff_payloads(previous: Optional[dict[str, Any]], current: dict[str, Any]) -> dict[str, Any]:
    curr_active = _active_findings(current)
    if previous is None:
        return {"baseline": None, "new": list(curr_active.values()), "resolved": [], "changed": [], "unchanged": [], "unknown": []}
    prev_active = _active_findings(previous)
    prev_index = _check_index(previous)
    curr_index = _check_index(current)
    before_config = previous.get("config") or {}
    after_config = current.get("config") or {}
    comparable = all(before_config.get(k) == after_config.get(k) for k in ("profile", "only", "skip", "no_crawl", "depth", "max_urls"))
    new, resolved, changed, unchanged, unknown = [], [], [], [], []
    for name in sorted(set(prev_active) | set(curr_active)):
        before = prev_active.get(name)
        after = curr_active.get(name)
        if before is None and after is not None:
            if name not in prev_index or str(prev_index[name].get("status", "")).lower() in {"error", "not_tested", "inconclusive"} or not comparable:
                unknown.append({"name": name, "reason": "No comparable successful baseline", "after": after})
            else:
                new.append(after)
        elif before is not None and after is None:
            state = str(curr_index.get(name, {}).get("status", "not_tested")).lower()
            evidence = str(curr_index.get(name, {}).get("evidence") or "").lower()
            if state in {"ok", "info"} and not any(x in evidence for x in ("skipped", "not tested", "no response", "unknown")) and comparable:
                resolved.append(before)
            else:
                unknown.append({"name": name, "reason": f"Current check state: {state}; scope comparable: {comparable}", "before": before})
        elif before is not None and after is not None:
            if any(x in str(after.get("evidence") or "").lower() for x in ("no response", "timeout", "not tested", "skipped")):
                unknown.append({"name": name, "reason": "Current check has no verified result", "before": before, "after": after})
            elif _fingerprint(before) == _fingerprint(after):
                unchanged.append(after)
            else:
                changed.append({"name": name, "before": before, "after": after})
    return {"baseline": {"target": previous.get("target"), "version": previous.get("version")}, "new": new, "resolved": resolved, "changed": changed, "unchanged": unchanged, "unknown": unknown}
