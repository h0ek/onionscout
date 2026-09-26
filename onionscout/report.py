from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import Any

from rich.table import Table

from .core import ASCII_LOGO, HTML_REPORT_MAX_RAW_CHARS
from .findings import group_for_finding_type, make_json_safe

def result_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    by_group: dict[str, int] = {}
    high_signal = []
    for item in results:
        status = str(item.get("status", "info"))
        risk = str(item.get("risk", "info"))
        group = str(item.get("group") or group_for_finding_type(item.get("finding_type", "info")))
        by_status[status] = by_status.get(status, 0) + 1
        by_risk[risk] = by_risk.get(risk, 0) + 1
        by_group[group] = by_group.get(group, 0) + 1
        if status in {"warn", "fail"} and risk in {"medium", "high", "critical"}:
            high_signal.append({
                "name": item.get("name"),
                "status": status,
                "risk": risk,
                "group": group,
                "evidence": item.get("evidence"),
            })
    return {
        "by_status": dict(sorted(by_status.items())),
        "by_risk": dict(sorted(by_risk.items())),
        "by_group": dict(sorted(by_group.items())),
        "high_signal": high_signal[:20],
    }

def _html_value(value: Any) -> str:
    safe = make_json_safe(value)
    if isinstance(safe, (dict, list)):
        text = json.dumps(safe, ensure_ascii=False, indent=2)
    else:
        text = str(safe)
    if len(text) > HTML_REPORT_MAX_RAW_CHARS:
        text = text[:HTML_REPORT_MAX_RAW_CHARS] + "\n...truncated..."
    return escape(text)

def render_html_report(target_url: str, results: list[dict[str, Any]], payload: dict[str, Any]) -> str:
    summary = result_summary(results)
    rows = []
    for item in results:
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('name', '')))}</td>"
            f"<td class='status-{escape(str(item.get('status', 'info')))}'>{escape(str(item.get('status', 'info')))}</td>"
            f"<td class='risk-{escape(str(item.get('risk', 'info')))}'>{escape(str(item.get('risk', 'info')))}</td>"
            f"<td>{escape(str(item.get('group') or group_for_finding_type(item.get('finding_type', 'info'))))}</td>"
            f"<td><pre>{_html_value(item.get('evidence'))}</pre></td>"
            "</tr>"
        )
    cards = []
    for title, data in (("Status", summary["by_status"]), ("Risk", summary["by_risk"]), ("Group", summary["by_group"])):
        inner = "".join(f"<div><strong>{escape(str(k))}</strong>: {escape(str(v))}</div>" for k, v in data.items())
        cards.append(f"<section class='card'><h2>{escape(title)}</h2>{inner or '<div>n/a</div>'}</section>")
    top = "".join(
        f"<li><strong>{escape(str(x.get('risk')))}</strong> {escape(str(x.get('name')))} <span>{escape(str(x.get('group')))}</span></li>"
        for x in summary["high_signal"]
    ) or "<li>No medium/high signal findings.</li>"
    generated = datetime.now(timezone.utc).isoformat()
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>onionscout report</title>
<style>
body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#101114;color:#e8e8e8;margin:0;padding:24px;}}
main{{max-width:1200px;margin:0 auto;}}
h1{{margin-bottom:4px;}}
.meta{{color:#aaa;margin-bottom:20px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:20px 0;}}
.card{{background:#181a20;border:1px solid #30333d;border-radius:12px;padding:14px;}}
table{{width:100%;border-collapse:collapse;background:#181a20;border:1px solid #30333d;border-radius:12px;overflow:hidden;}}
th,td{{border-bottom:1px solid #30333d;padding:10px;text-align:left;vertical-align:top;}}
th{{background:#20232b;}}
pre{{white-space:pre-wrap;word-break:break-word;margin:0;max-width:640px;}}
.status-ok,.risk-info{{color:#7bd88f;}}
.status-info,.risk-low{{color:#8cc7ff;}}
.status-warn,.risk-medium{{color:#ffd166;}}
.status-fail,.status-error,.risk-high,.risk-critical{{color:#ff6b6b;}}
ul{{background:#181a20;border:1px solid #30333d;border-radius:12px;padding:14px 14px 14px 34px;}}
span{{color:#aaa;}}
</style>
</head>
<body>
<main>
<h1>onionscout report</h1>
<div class="meta">Target: {escape(target_url)} · Generated: {escape(generated)} · Version: {escape(str(payload.get('version', 'n/a')))}</div>
<div class="grid">{''.join(cards)}</div>
<h2>Top signal</h2>
<ul>{top}</ul>
<h2>Findings</h2>
<table>
<thead><tr><th>Check</th><th>Status</th><th>Risk</th><th>Group</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</main>
</body>
</html>
'''

def render_text_evidence(ev: Any) -> str:
    ev = make_json_safe(ev)
    if isinstance(ev, list):
        return " | ".join(str(x) for x in ev)
    if isinstance(ev, dict):
        return json.dumps(ev, ensure_ascii=False)
    return str(ev)

def render_txt_report(target_url: str, results: list[dict[str, Any]]) -> str:
    lines = [ASCII_LOGO.strip("\n"), "", f"Target: {target_url}", ""]
    for item in results:
        lines.append(f"== {item['name']} ==")
        lines.append(f"status={item['status']} risk={item['risk']} type={item['finding_type']}")
        lines.append(render_text_evidence(item["evidence"]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

def _style_status(status: str) -> str:
    return {
        "ok": "green",
        "info": "bright_blue",
        "warn": "orange1",
        "fail": "red",
        "error": "bold red",
    }.get((status or "info").lower(), "white")

def _style_risk(risk: str) -> str:
    return {
        "info": "bright_blue",
        "low": "yellow",
        "medium": "orange1",
        "high": "red",
        "critical": "bold red",
    }.get((risk or "info").lower(), "white")

def _style_type(finding_type: str) -> str:
    return {
        "info": "bright_blue",
        "network": "cyan",
        "internal": "dim red",
        "dependency": "magenta",
        "external_links": "cyan",
        "deanon": "bold red",
        "policy": "yellow",
        "leak": "orange1",
    }.get((finding_type or "info").lower(), "white")

def _cell(value: Any, style: str) -> str:
    text = str(value)
    return f"[{style}]{text}[/{style}]"

def status_cell(status: str) -> str:
    return _cell(status, _style_status(status))

def risk_cell(risk: str) -> str:
    return _cell(risk, _style_risk(risk))

def type_cell(finding_type: str) -> str:
    return _cell(finding_type, _style_type(finding_type))
