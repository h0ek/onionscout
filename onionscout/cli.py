from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Optional
from urllib.parse import urlparse

from rich.table import Table

from .checks.analytics import check_analytics_ids
from .checks.api import check_api_exposure
from .checks.cloud import check_infrastructure_correlation
from .checks.files import (
    _fetch_security_txt,
    check_backup_archives,
    check_directory_listing,
    check_error_page_fingerprints,
    check_files_and_paths,
    check_http_methods,
    check_status_pages,
    check_well_known,
)
from .checks.fingerprinting import check_browser_fingerprinting
from .checks.headers import (
    analyze_set_cookie,
    check_cors,
    check_csp_related,
    check_header_leaks,
    check_http_availability,
    check_onion_location,
    check_proxy_headers,
    check_security_headers,
)
from .checks.iframes import check_iframes_and_suspicious_js
from .checks.javascript import (
    check_captcha_leak,
    check_external_resources,
    check_form_actions,
    check_js_leaks,
    check_meta_redirects,
    check_protocol_relative_links,
    check_websocket_endpoints,
    collect_javascript_sources,
)
from .checks.metadata import (
    check_comments,
    check_document_metadata,
    check_image_metadata,
    check_meta_and_link_leaks,
    check_robots_sitemap,
)
from .checks.ssh import check_ssh_fingerprint
from .checks.tls import check_https_tls
from .checks.web import (
    check_cookie_present,
    check_etag,
    check_favicon,
    check_favicon_in_html,
    check_target_onion_address,
    check_tor_proxy,
    detect_server,
)
from .core import (
    ASCII_LOGO,
    CHECK_KEY_ALIASES,
    PROFILE_CHECK_KEYS,
    SAFE_CHECK_KEYS,
    SelectolaxHTMLParser,
    VERSION,
    cfg,
    choose_working_origin,
    configure_tor_proxy,
    configure_transparent_tor,
    rebuild_retry_adapter,
    console,
    normalize_url,
    parse_socks,
    preflight_tor_socks,
    set_cookie_header,
)
from .crawler import crawl_finding, indicator_finding
from .findings import error_finding, finding, group_for_finding_type, make_json_safe
from .history import diff_payloads, latest_scan, list_scans, save_scan
from .report import (
    render_html_report,
    render_text_evidence,
    render_txt_report,
    result_summary,
    risk_cell,
    status_cell,
    type_cell,
)


def _split_csv_values(value: Optional[str]) -> set[str]:
    if not value:
        return set()
    out = set()
    for chunk in value.replace(",", " ").split():
        item = chunk.strip().lower()
        if item:
            out.add(CHECK_KEY_ALIASES.get(item, item))
    return out


def filter_tasks(tasks: list[dict[str, Any]], profile: str, only_value: Optional[str], skip_value: Optional[str]) -> list[dict[str, Any]]:
    profile_keys = PROFILE_CHECK_KEYS.get(profile, SAFE_CHECK_KEYS)
    only = _split_csv_values(only_value)
    skip = _split_csv_values(skip_value)
    available = {t["key"] for t in tasks}
    wanted = (only & available) if only else (set(profile_keys) & available)
    return [task for task in tasks if task["key"] in wanted and task["key"] not in skip]


def run_step(idx: int, total: int, desc: str, fn, json_mode: bool) -> dict[str, Any]:
    if json_mode:
        try:
            return fn()
        except Exception as e:
            return error_finding(desc, e)

    with console.status(f"[bright_blue]{idx}/{total} running: {desc}[/bright_blue]", spinner="dots"):
        try:
            out = fn()
        except Exception as e:
            out = error_finding(desc, e)

    name = out.get("name", desc)
    console.print(f"[green]✓ {idx}/{total} complete: {name}[/green]")
    return out


def show_help() -> None:
    console.print(ASCII_LOGO)
    console.print("Lightweight CLI for basic Tor hidden-service (.onion) security checks\n")
    console.print("usage:")
    console.print("  onionscout [options] -u URL\n")


class CustomParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        super().__init__(add_help=False, **kwargs)

    def print_usage(self, file=None):
        return None

    def error(self, message):
        console.print(ASCII_LOGO)
        console.print(f"[red]Error: {message}[/red]\n")
        self.print_help()
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = CustomParser(description="CLI tool for Tor hidden-service (.onion) security checks")
    parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("-u", "--url", required=True, help=".onion URL to scan (e.g. abcdef.onion or abcdef.onion:8080)")
    parser.add_argument("--http-timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10.0)")
    parser.add_argument("--ssh-timeout", type=float, default=10.0, help="SSH timeout in seconds (default: 10.0)")
    parser.add_argument("--tls-timeout", type=float, default=12.0, help="TLS timeout in seconds (default: 12.0)")
    parser.add_argument("-s", "--sleep", type=float, default=1.0, help="minimum seconds between HTTP requests (default: 1.0)")
    parser.add_argument("--tor-mode", choices=["socks", "transparent"], default="socks", help="Tor transport mode: socks or transparent (default: socks)")
    parser.add_argument("--socks", default="127.0.0.1:9050", help="Tor SOCKS5h proxy for --tor-mode socks (default: 127.0.0.1:9050)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port for fingerprint check (default: 22)")
    parser.add_argument("--skip-tor-check", action="store_true", help="skip external Tor Project verification in SOCKS mode; unavailable in transparent mode")
    parser.add_argument("--json", action="store_true", help="output JSON instead of a table")
    parser.add_argument("--html-report", help="write an HTML report to file")
    parser.add_argument("--profile", choices=["basic", "safe", "extended"], default="safe", help="check profile (default: safe)")
    parser.add_argument("--only", help="run only selected checks, comma-separated, e.g. headers,js,robots")
    parser.add_argument("--skip", help="skip selected checks, comma-separated, e.g. ssh,images,crawl")
    parser.add_argument("--cookie", help="raw Cookie header, e.g. 'a=b; c=d'")
    parser.add_argument("--clearnet-url", help="optional clearnet mirror URL for Onion-Location validation")
    parser.add_argument("-o", "--output", help="write report to file (JSON if --json, else TXT)")
    parser.add_argument("--insecure-https", action="store_true", help="disable HTTPS certificate verification for target onion requests only")
    parser.add_argument("--no-auto-insecure-https", action="store_true", help="do not automatically disable HTTPS verification for self-signed target onion certificates")
    parser.add_argument("--scheme", choices=["auto", "http", "https"], default="auto", help="origin scheme mode (default: auto)")
    parser.add_argument("--retries", type=int, default=2, help="network retries for transient onion errors (default: 2)")
    parser.add_argument("--workers", type=int, default=1, help="reserved compatibility option; crawler is sequential")
    parser.add_argument("--max-requests", type=int, default=350, help="maximum HTTP requests per scan (default: 350)")
    parser.add_argument("--max-body-bytes", type=int, default=2000000, help="maximum decompressed bytes per HTTP response (default: 2000000)")
    parser.add_argument("--max-duration", type=float, default=900.0, help="maximum scan duration in seconds (default: 900)")
    parser.add_argument("--no-crawl", action="store_true", help="disable crawler-based checks")
    parser.add_argument("--max-urls", type=int, default=80, help="crawler max URLs (default: 80)")
    parser.add_argument("--depth", type=int, default=1, help="crawler depth (default: 1)")
    parser.add_argument("--save-scan", action="store_true", help="save this scan to local history")
    parser.add_argument("--diff", action="store_true", help="compare with the latest saved scan and save this scan")
    parser.add_argument("--history", action="store_true", help="show saved scan history for the target and exit")
    parser.add_argument("--history-limit", type=int, default=10, help="history rows to show (default: 10)")
    parser.add_argument("--history-db", help="custom SQLite history database path")
    return parser


def _show_history(target: str, rows: list[dict[str, Any]], json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(make_json_safe({"target": target, "history": rows}), ensure_ascii=False, indent=2))
        return
    console.print(ASCII_LOGO)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID")
    table.add_column("Scanned")
    table.add_column("Version")
    table.add_column("Warn")
    table.add_column("Fail")
    table.add_column("High signal")
    for row in rows:
        summary = row.get("summary") or {}
        by_status = summary.get("by_status") or {}
        table.add_row(
            str(row.get("id")),
            str(row.get("scanned_at")),
            str(row.get("version")),
            str(by_status.get("warn", 0)),
            str(by_status.get("fail", 0)),
            str(len(summary.get("high_signal") or [])),
        )
    if rows:
        console.print(table)
    else:
        console.print("[cyan]No saved scans for this target.[/cyan]")


def _show_diff(diff: dict[str, Any]) -> None:
    baseline = diff.get("baseline")
    if baseline is None:
        console.print("\n[yellow]Diff: no previous saved scan; current findings are the baseline.[/yellow]")
    else:
        console.print(f"\n[bold cyan]Diff against previous saved scan ({baseline.get('version', 'unknown')})[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Change")
    table.add_column("Check")
    table.add_column("Risk")
    table.add_column("Status")
    table.add_column("Evidence")
    rows = 0
    for label, key in (("NEW", "new"), ("RESOLVED", "resolved"), ("CHANGED", "changed"), ("UNKNOWN", "unknown"), ("UNCHANGED", "unchanged")):
        for item in diff.get(key) or []:
            current = (item.get("after") or item.get("before") or item) if key in {"changed", "unknown"} else item
            table.add_row(
                label,
                str(current.get("name", "unknown")),
                str(current.get("risk", "info")),
                str(current.get("status", "info")),
                render_text_evidence(current.get("evidence")),
            )
            rows += 1
    if rows:
        console.print(table)
    else:
        console.print("[green]No active warning/failure findings to compare.[/green]")


def main() -> None:
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args()

    try:
        target_input = normalize_url(args.url)
    except Exception as e:
        console.print(ASCII_LOGO)
        console.print(f"[red]Error: {e}[/red]\n")
        parser.print_help()
        sys.exit(1)

    available_checks = set(SAFE_CHECK_KEYS) | set(PROFILE_CHECK_KEYS["basic"])
    invalid = (_split_csv_values(args.only) | _split_csv_values(args.skip)) - available_checks
    if invalid:
        parser.error("Unknown checks: " + ", ".join(sorted(invalid)))
    if args.history:
        rows = list_scans(target_input, args.history_db, max(1, args.history_limit))
        _show_history(target_input, rows, args.json)
        return

    cfg.http_timeout = args.http_timeout
    cfg.ssh_timeout = args.ssh_timeout
    cfg.tls_timeout = args.tls_timeout
    cfg.sleep = args.sleep
    cfg.insecure_https = args.insecure_https
    cfg.auto_insecure_https = not args.no_auto_insecure_https
    cfg.auto_insecure_https_reason = None
    cfg.no_crawl = args.no_crawl
    cfg.crawl_max_urls = max(1, args.max_urls)
    cfg.crawl_depth = max(0, args.depth)
    cfg.scheme = args.scheme
    cfg.retries = max(0, args.retries)
    cfg.workers = 1
    cfg.max_requests = max(1, args.max_requests)
    cfg.max_body_bytes = max(1024, args.max_body_bytes)
    cfg.max_duration = max(1.0, args.max_duration)
    cfg.requests_made = 0
    cfg.response_cache = {}
    cfg.started_at = time.monotonic()
    rebuild_retry_adapter()
    cfg.profile = args.profile
    cfg.cookie_header = None
    cfg.clearnet_url = None

    if args.clearnet_url:
        clearnet_url = args.clearnet_url.strip()
        if not clearnet_url.startswith(("http://", "https://")):
            clearnet_url = "https://" + clearnet_url
        cfg.clearnet_url = clearnet_url.rstrip("/")

    if args.tor_mode == "transparent" and args.skip_tor_check:
        parser.error("--skip-tor-check cannot be used with --tor-mode transparent")

    if args.tor_mode == "socks":
        try:
            socks_host, socks_port = parse_socks(args.socks)
            cfg.socks_host, cfg.socks_port = socks_host, socks_port
            configure_tor_proxy(socks_host, socks_port)
            preflight_tor_socks(socks_host, socks_port, min(cfg.http_timeout, 5.0))
        except Exception as e:
            message = f"Tor SOCKS preflight failed: {e}"
            if args.json:
                print(json.dumps({"tool": "onionscout", "version": VERSION, "status": "error", "error": message}, ensure_ascii=False, indent=2))
            else:
                console.print(ASCII_LOGO)
                console.print(f"[red]Error: {message}[/red]")
                console.print("[red]Scan aborted before contacting the target.[/red]")
            sys.exit(1)
    else:
        configure_transparent_tor()

    if args.skip_tor_check:
        tor_check_result = finding("SOCKS/Tor connectivity check", "info", "info", "External Tor Project verification skipped; local SOCKS5 preflight passed")
    else:
        tor_check_result = check_tor_proxy()
        if tor_check_result.get("status") != "ok":
            message = f"Tor connectivity verification failed: {tor_check_result.get('evidence', 'unknown error')}"
            if args.json:
                print(json.dumps(make_json_safe({"tool": "onionscout", "version": VERSION, "status": "error", "error": message}), ensure_ascii=False, indent=2))
            else:
                console.print(ASCII_LOGO)
                console.print(f"[red]Error: {message}[/red]")
                if args.tor_mode == "transparent":
                    console.print("[red]Scan aborted before contacting the target. Transparent mode requires verified Tor egress.[/red]")
                else:
                    console.print("[red]Scan aborted before contacting the target. Use --skip-tor-check only when external Tor Project verification is intentionally unavailable.[/red]")
            sys.exit(1)

    if args.cookie:
        set_cookie_header(args.cookie)

    cfg.target_host = (urlparse(target_input).hostname or "").lower()
    cfg.target_port = urlparse(target_input).port
    base_url, origin_info = choose_working_origin(target_input, cfg.scheme)

    if not args.json:
        console.print(ASCII_LOGO)
        if origin_info.get("note"):
            console.print(f"[yellow]Origin selection: {origin_info.get('note')}[/yellow]")

    crawled_urls: list[str] = []
    js_bundle: Optional[dict[str, Any]] = None

    def run_crawl_step() -> dict[str, Any]:
        nonlocal crawled_urls
        crawl_res, urls = crawl_finding(base_url)
        crawled_urls = urls
        return crawl_res

    def run_indicator_step() -> dict[str, Any]:
        return indicator_finding(crawled_urls)

    def get_js_bundle() -> dict[str, Any]:
        nonlocal js_bundle
        if js_bundle is None:
            js_bundle = collect_javascript_sources(base_url)
        return js_bundle

    tasks: list[dict[str, Any]] = [
        {"key": "tor", "name": "SOCKS/Tor connectivity check", "fn": lambda: tor_check_result},
    ]

    tasks += [
        {"key": "cookie-provided", "name": "Cookie provided", "fn": lambda: check_cookie_present(args.cookie)},
        {"key": "target-onion", "name": "Target onion address", "fn": lambda: check_target_onion_address(base_url)},
        {"key": "origin-selection", "name": "Origin selection", "fn": lambda: finding("Origin selection", "info", "info", origin_info)},
        {"key": "http-availability", "name": "HTTP origin availability", "fn": lambda: check_http_availability(base_url)},
        {"key": "detect-server", "name": "Detect server", "fn": lambda: detect_server(base_url)},
        {"key": "https-tls", "name": "HTTPS/TLS sanity", "fn": lambda: check_https_tls(base_url)},
        {"key": "favicon", "name": "Detect favicon", "fn": lambda: check_favicon(base_url)},
        {"key": "favicon-html", "name": "Favicon in HTML", "fn": lambda: check_favicon_in_html(base_url)},
        {"key": "etag", "name": "ETag header", "fn": lambda: check_etag(base_url)},
        {"key": "onion-location", "name": "Onion-Location header", "fn": lambda: check_onion_location(base_url)},
        {"key": "header-leaks", "name": "Header leaks", "fn": lambda: check_header_leaks(base_url)},
        {"key": "security-headers", "name": "Security headers", "fn": lambda: check_security_headers(base_url)},
        {"key": "ssh", "name": "SSH fingerprint", "fn": lambda: check_ssh_fingerprint(base_url, args.ssh_port)},
        {"key": "comments", "name": "Comments in code", "fn": lambda: check_comments(base_url)},
        {"key": "status-pages", "name": "Status pages", "fn": lambda: check_status_pages(base_url)},
        {"key": "http-methods", "name": "HTTP methods", "fn": lambda: check_http_methods(base_url)},
        {"key": "files-paths", "name": "Files & paths", "fn": lambda: check_files_and_paths(base_url)},
        {"key": "backup-archives", "name": "Backup/archive leaks", "fn": lambda: check_backup_archives(base_url)},
        {"key": "directory-listing", "name": "Directory listing", "fn": lambda: check_directory_listing(base_url)},
        {"key": "well-known", "name": "Well-known endpoints", "fn": lambda: check_well_known(base_url)},
        {"key": "api-exposure", "name": "API / debug exposure", "fn": lambda: check_api_exposure(base_url)},
        {"key": "external-resources", "name": "External resources", "fn": lambda: check_external_resources(base_url)},
        {"key": "protocol-relative", "name": "Protocol-relative links", "fn": lambda: check_protocol_relative_links(base_url)},
        {"key": "cors", "name": "CORS headers", "fn": lambda: check_cors(base_url)},
        {"key": "meta-refresh", "name": "Meta-refresh", "fn": lambda: check_meta_redirects(base_url)},
        {"key": "robots-sitemap", "name": "Robots & sitemap", "fn": lambda: check_robots_sitemap(base_url)},
        {"key": "form-actions", "name": "Form actions", "fn": lambda: check_form_actions(base_url)},
        {"key": "websockets", "name": "WebSocket endpoints", "fn": lambda: check_websocket_endpoints(base_url)},
        {"key": "js-leaks", "name": "JavaScript leaks", "fn": lambda: check_js_leaks(base_url, get_js_bundle())},
        {"key": "fingerprinting-js", "name": "Browser fingerprinting APIs", "fn": lambda: check_browser_fingerprinting(base_url, get_js_bundle())},
        {"key": "infrastructure", "name": "Infrastructure correlation", "fn": lambda: check_infrastructure_correlation(base_url, get_js_bundle())},
        {"key": "analytics-ids", "name": "Analytics identifiers", "fn": lambda: check_analytics_ids(base_url, get_js_bundle())},
        {"key": "iframes-js", "name": "Iframes / suspicious JavaScript", "fn": lambda: check_iframes_and_suspicious_js(base_url, get_js_bundle())},
        {"key": "image-metadata", "name": "Image metadata", "fn": lambda: check_image_metadata(base_url)},
        {"key": "proxy-headers", "name": "Proxy headers", "fn": lambda: check_proxy_headers(base_url)},
        {"key": "securitytxt-root", "name": "security.txt (root)", "fn": lambda: _fetch_security_txt(base_url, "/security.txt")},
        {"key": "securitytxt-well-known", "name": "security.txt (.well-known)", "fn": lambda: _fetch_security_txt(base_url, "/.well-known/security.txt")},
        {"key": "captcha", "name": "CAPTCHA leak", "fn": lambda: check_captcha_leak(base_url)},
        {"key": "csp-related", "name": "CSP / Report-To / NEL / Link", "fn": lambda: check_csp_related(base_url)},
        {"key": "metadata-leaks", "name": "Canonical / OG / RSS / JSON-LD leaks", "fn": lambda: check_meta_and_link_leaks(base_url)},
        {"key": "set-cookie", "name": "Set-Cookie analysis", "fn": lambda: analyze_set_cookie(base_url)},
        {"key": "error-pages", "name": "Error page fingerprints", "fn": lambda: check_error_page_fingerprints(base_url)},
        {"key": "crawl", "name": "Crawl links", "fn": run_crawl_step},
        {"key": "document-metadata", "name": "Document metadata", "fn": lambda: check_document_metadata(base_url, crawled_urls)},
        {"key": "indicators", "name": "Indicators (emails/crypto)", "fn": run_indicator_step},
    ]

    tasks = filter_tasks(tasks, args.profile, args.only, args.skip)
    keys = {task["key"] for task in tasks}
    known = set(PROFILE_CHECK_KEYS["safe"]) | set(PROFILE_CHECK_KEYS["basic"]) | {"tor", "indicators"}
    unknown_checks = (_split_csv_values(args.only) | _split_csv_values(args.skip)) - (known | keys)
    if unknown_checks:
        parser.error("Unknown checks: " + ", ".join(sorted(unknown_checks)))
    if "indicators" in keys and "crawl" not in keys and not args.no_crawl:
        for task in tasks:
            if task["key"] == "indicators":
                original = task["fn"]
                task["fn"] = lambda fn=original: (run_crawl_step(), fn())[1]
    if not tasks:
        console.print(ASCII_LOGO)
        console.print("[red]Error: no checks selected after applying --profile/--only/--skip[/red]")
        sys.exit(2)

    results = []
    total = len(tasks)
    for idx, task in enumerate(tasks, start=1):
        results.append(run_step(idx, total, task["name"], task["fn"], args.json))

    payload = {
        "tool": "onionscout",
        "version": VERSION,
        "target": base_url,
        "config": {
            "http_timeout": cfg.http_timeout,
            "ssh_timeout": cfg.ssh_timeout,
            "tls_timeout": cfg.tls_timeout,
            "sleep": cfg.sleep,
            "tor_mode": cfg.tor_mode,
            "socks": f"{cfg.socks_host}:{cfg.socks_port}" if cfg.tor_mode == "socks" else None,
            "insecure_https": cfg.insecure_https,
            "auto_insecure_https": cfg.auto_insecure_https,
            "auto_insecure_https_reason": cfg.auto_insecure_https_reason,
            "no_crawl": cfg.no_crawl,
            "max_urls": cfg.crawl_max_urls,
            "depth": cfg.crawl_depth,
            "scheme": cfg.scheme,
            "retries": cfg.retries,
            "workers": cfg.workers,
            "max_requests": cfg.max_requests,
            "max_body_bytes": cfg.max_body_bytes,
            "max_duration": cfg.max_duration,
            "profile": cfg.profile,
            "only": args.only,
            "skip": args.skip,
            "cookie_scoped_to_target": bool(cfg.cookie_header),
            "clearnet_url": cfg.clearnet_url,
            "html_parser": "selectolax" if SelectolaxHTMLParser is not None else "stdlib",
            "origin_selection": origin_info,
        },
        "summary": result_summary(results),
        "results": results,
    }

    saved_scan_id = None
    if args.diff:
        previous = latest_scan(base_url, args.history_db)
        payload["diff"] = diff_payloads(previous.get("payload") if previous else None, payload)
        saved_scan_id = save_scan(payload, args.history_db)
    elif args.save_scan:
        saved_scan_id = save_scan(payload, args.history_db)
    if saved_scan_id is not None:
        payload["saved_scan_id"] = saved_scan_id

    if args.json:
        out_json = json.dumps(make_json_safe(payload), ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_json + "\n")
        else:
            print(out_json)
        if args.html_report:
            with open(args.html_report, "w", encoding="utf-8") as f:
                f.write(render_html_report(base_url, results, payload))
        return

    console.print("\n[bold green]All steps complete[/bold green]\n")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Risk")
    table.add_column("Type")
    table.add_column("Group")
    table.add_column("Evidence")
    for item in results:
        table.add_row(
            item["name"],
            status_cell(item["status"]),
            risk_cell(item["risk"]),
            type_cell(item["finding_type"]),
            str(item.get("group") or group_for_finding_type(item.get("finding_type", "info"))),
            render_text_evidence(item["evidence"]),
        )
    console.print(table)

    if args.diff:
        _show_diff(payload["diff"])
    if saved_scan_id is not None:
        console.print(f"[cyan]Saved scan history ID: {saved_scan_id}[/cyan]")

    if args.output:
        txt = render_html_report(base_url, results, payload) if args.output.lower().endswith((".html", ".htm")) else render_txt_report(base_url, results)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(txt)
        console.print(f"\n[cyan]Saved report to: {args.output}[/cyan]")

    if args.html_report:
        with open(args.html_report, "w", encoding="utf-8") as f:
            f.write(render_html_report(base_url, results, payload))
        console.print(f"[cyan]Saved HTML report to: {args.html_report}[/cyan]")


if __name__ == "__main__":
    main()
