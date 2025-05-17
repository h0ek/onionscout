#!/usr/bin/env python3
import sys
import re
import socket
import requests
import mmh3
import paramiko
from urllib.parse import urlparse
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.console import Console

console = Console()

def show_help():
    ascii_logo = """
 ▗▄▖ ▄▄▄▄  ▄  ▄▄▄  ▄▄▄▄       ▗▄▄▖▗▞▀▘ ▄▄▄  █  ▐▌   ■  
▐▌ ▐▌█   █ ▄ █   █ █   █     ▐▌   ▝▚▄▖█   █ ▀▄▄▞▘▗▄▟▙▄▖
▐▌ ▐▌█   █ █ ▀▄▄▄▀ █   █      ▝▀▚▖    ▀▄▄▄▀        ▐▌  
▝▚▄▞▘      █                 ▗▄▄▞▘                 ▐▌  
                                                   ▐▌  
"""
    console.print(ascii_logo)
    console.print("Usage:")
    console.print("  onionscout -h")
    console.print("  onionscout -u <ONION_URL>")
    console.print("  onionscout -u -tor <ONION_URL>")

def get(url, proxies=None, **kwargs):
    return requests.get(url, proxies=proxies, timeout=10, **kwargs)

def check_tor_proxy():
    try:
        r = requests.get(
            "http://check.torproject.org",
            proxies={"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"},
            timeout=5
        )
        return "Congratulations" in r.text
    except:
        return False

def detect_server(url, proxies):
    try:
        r = get(url, proxies)
        hdr = r.headers.get("Server", "")
        err = r.text.lower() if r.status_code == 404 else ""
        out = []
        if hdr:
            out.append(f"Web server header: {hdr}")
        if "apache" in err:
            out.append("Web server (error page): Apache")
        elif "nginx" in err:
            out.append("Web server (error page): Nginx")
        elif "lighttpd" in err:
            out.append("Web server (error page): Lighttpd")
        return "\n".join(out) or "Web server not detected."
    except Exception as e:
        return f"Error connecting: {e}"

def detect_favicon(url, proxies):
    ico = url.rstrip("/") + "/favicon.ico"
    try:
        r = get(ico, proxies)
        if r.status_code == 200:
            h = mmh3.hash(r.content)
            return f"Favicon found at {ico}. MurmurHash3: {h}"
        return "No favicon at /favicon.ico"
    except:
        return "No favicon at /favicon.ico"

def detect_favicon_in_html(url, proxies):
    try:
        r = get(url, proxies)
        m = re.search(r'<link\s+rel=["\']icon["\']\s+href=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        if m:
            link = m.group(1)
            fav = link if link.startswith("http") else url.rstrip("/") + link
            rf = get(fav, proxies)
            if rf.status_code == 200:
                return f"Favicon in HTML: {fav}. MurmurHash3: {mmh3.hash(rf.content)}"
        return "No favicon in HTML"
    except Exception as e:
        return f"Error parsing HTML favicon: {e}"

def check_ssh_fingerprint(host):
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=22, username="", password="", timeout=10)
        fp = c.get_transport().get_remote_server_key().get_fingerprint()
        hexfp = ":".join(f"{b:02x}" for b in fp)
        c.close()
        return f"SSH Fingerprint: {hexfp}"
    except:
        return "SSH Fingerprint not available"

def check_comments(url, proxies):
    try:
        r = get(url, proxies)
        cs = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
        if not cs:
            return "No comments in code"
        out = ["Comments in code:"]
        for c in cs:
            for l in c.splitlines():
                out.append(l.strip())
        return "\n".join(out)
    except Exception as e:
        return f"Error checking comments: {e}"

def check_status_pages(url, proxies):
    pages = {
        "/server-status": "Apache mod_status/info",
        "/server-info":  "Apache mod_status/info",
        "/status":       "nginx stub_status",
        "/webdav":       "nginx dav"
    }
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    res = []
    for p, desc in pages.items():
        u = url.rstrip("/") + p
        try:
            r = get(u, proxies)
            if r.status_code == 200:
                line = f"{p} ({desc}) accessible"
                m = ip_re.search(r.text)
                if m:
                    line += f"; leaked IP: {m.group()}"
                res.append(line)
        except:
            pass
    return "\n".join(res) or "No status pages found"

def check_files_and_paths(url, proxies):
    files = ["info.php", ".git", ".svn", ".hg", ".env", ".DS_Store", "security.txt"]
    paths = ["backup", "admin", "secret"]
    found = []
    for f in files:
        u = url.rstrip("/") + "/" + f
        try:
            if get(u, proxies).status_code == 200:
                found.append(f"File found: /{f}")
        except:
            pass
    for p in paths:
        u = url.rstrip("/") + "/" + p
        try:
            if get(u, proxies).status_code == 200:
                found.append(f"Path found: /{p}")
        except:
            pass
    return "\n".join(found) or "No sensitive files or paths found"

def check_external_resources(url, proxies):
    try:
        r = get(url, proxies)
        links = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', r.text)
        out = []
        for link in set(links):
            host = urlparse(link).hostname or ""
            if not host.endswith(".onion"):
                out.append(link)
        return "External resources loaded:\n" + "\n".join(out) if out else "No external resources detected"
    except Exception as e:
        return f"Error checking external resources: {e}"

def check_cors(url, proxies):
    try:
        r = get(url, proxies)
        acao = r.headers.get("Access-Control-Allow-Origin")
        return f"CORS header Access-Control-Allow-Origin: {acao}" if acao else "No CORS header"
    except Exception as e:
        return f"Error checking CORS headers: {e}"

def check_meta_redirects(url, proxies):
    try:
        r = get(url, proxies)
        metas = re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', r.text, re.IGNORECASE)
        out = []
        for m in metas:
            cont = re.search(r'content=["\']([^"\']+)["\']', m, re.IGNORECASE)
            if cont and "url=" in cont.group(1).lower():
                target = cont.group(1).split("url=")[1]
                if target.startswith("http://") or target.startswith("https://"):
                    out.append(target)
        return "Meta-refresh redirects to:\n" + "\n".join(out) if out else "No meta-refresh to clearnet URLs"
    except Exception as e:
        return f"Error checking meta-refresh: {e}"

def check_robots_sitemap(url, proxies):
    out = []
    for path in ["/robots.txt", "/sitemap.xml"]:
        u = url.rstrip("/") + path
        try:
            r = get(u, proxies)
            if r.status_code == 200:
                if path == "/robots.txt":
                    lines = [l for l in r.text.splitlines() if l.lower().startswith(("disallow:", "sitemap:"))]
                    if lines:
                        out.append(f"{path} entries:\n" + "\n".join(lines))
                else:
                    locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
                    if locs:
                        out.append(f"{path} locs:\n" + "\n".join(locs))
        except:
            pass
    return "\n\n".join(out) or "No robots.txt or sitemap.xml entries found"

def check_form_actions(url, proxies):
    try:
        r = get(url, proxies)
        acts = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        out = []
        for a in set(acts):
            if a.startswith("http://") or a.startswith("https://"):
                if ".onion" not in urlparse(a).hostname:
                    out.append(a)
        return "Form actions to clearnet:\n" + "\n".join(out) if out else "No clearnet form actions"
    except Exception as e:
        return f"Error checking form actions: {e}"

def check_websocket_endpoints(url, proxies):
    try:
        r = get(url, proxies)
        wss = re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', r.text)
        out = []
        for ws in set(wss):
            host = urlparse(ws).hostname or ""
            if not host.endswith(".onion"):
                out.append(ws)
        return "WebSocket endpoints to clearnet:\n" + "\n".join(out) if out else "No clearnet WebSocket endpoints"
    except Exception as e:
        return f"Error checking WebSocket endpoints: {e}"

def check_proxy_headers(url, proxies):
    try:
        r = get(url, proxies)
        keys = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded"]
        found = [f"{k}: {r.headers[k]}" for k in keys if k in r.headers]
        return "\n".join(found) if found else "No proxy-related headers"
    except Exception as e:
        return f"Error checking proxy headers: {e}"

def check_security_txt(url, proxies):
    try:
        u = url.rstrip("/") + "/.well-known/security.txt"
        r = get(u, proxies)
        return "security.txt:\n" + r.text.strip() if r.status_code == 200 else "security.txt not found"
    except Exception as e:
        return f"Error checking security.txt: {e}"

def check_captcha_leak(url, proxies=None):
    try:
        r = get(url, proxies)
        if r.status_code != 200:
            return "No page to check for CAPTCHA leaks"
        text = r.text.lower()
        leaks = set()
        for match in re.findall(r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, re.IGNORECASE):
            leaks.add(match)
        for path in ("/lua/cap.lua", "/queue.html"):
            if path in text:
                for m in re.findall(r'["\']([^"\']+' + re.escape(path) + r')["\']', text):
                    full = m if m.startswith("http") else url.rstrip("/") + m
                    leaks.add(full)
        real_leaks = [u for u in leaks if not urlparse(u).hostname.endswith(".onion")]
        if not real_leaks:
            return "No external CAPTCHA resources detected"
        return "Possible CAPTCHA leaks:\n  " + "\n  ".join(real_leaks)
    except Exception as e:
        return f"Error checking CAPTCHA leaks: {e}"

def main():
    if "-h" in sys.argv:
        show_help()
        return
    if "-u" not in sys.argv:
        console.print("Check -h for usage")
        return

    url = sys.argv[sys.argv.index("-u")+1]
    use_tor = "-tor" in sys.argv

    proxies = None
    tasks = []

    # Build task list
    if use_tor:
        tasks.append(("Check Tor proxy", lambda: "OK" if check_tor_proxy() else "FAILED"))
    else:
        tasks.append(("Skip Tor proxy", lambda: "SKIPPED"))

    tasks.extend([
        ("Detect server", lambda: detect_server(url, proxies)),
        ("Detect favicon", lambda: detect_favicon(url, proxies)),
        ("Favicon in HTML", lambda: detect_favicon_in_html(url, proxies)),
        ("SSH fingerprint", lambda: check_ssh_fingerprint(url)),
        ("Comments in code", lambda: check_comments(url, proxies)),
        ("Status pages", lambda: check_status_pages(url, proxies)),
        ("Files & paths", lambda: check_files_and_paths(url, proxies)),
        ("External resources", lambda: check_external_resources(url, proxies)),
        ("CORS headers", lambda: check_cors(url, proxies)),
        ("Meta-refresh", lambda: check_meta_redirects(url, proxies)),
        ("Robots & sitemap", lambda: check_robots_sitemap(url, proxies)),
        ("Form actions", lambda: check_form_actions(url, proxies)),
        ("WebSocket endpoints", lambda: check_websocket_endpoints(url, proxies)),
        ("Proxy headers", lambda: check_proxy_headers(url, proxies)),
        ("security.txt", lambda: check_security_txt(url, proxies)),
        ("CAPTCHA leak", lambda: check_captcha_leak(url, proxies)),
    ])

    # Perform tasks with progress
    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as prog:
        task = prog.add_task("", total=len(tasks))
        for desc, fn in tasks:
            prog.update(task, description=f"[cyan]{desc}: in progress")
            try:
                out = fn()
                status = "done" if not out.lower().startswith("error") and out not in ("FAILED",) else "failed"
            except Exception:
                out = "Error during task"
                status = "failed"
            prog.update(task, description=f"[cyan]{desc}: [green]{status}" if status=="done" else f"[cyan]{desc}: [red]{status}")
            prog.advance(task)
            results.append((desc, out))

    console.print("\n[bold]Results:[/bold]")
    for desc, out in results:
        console.print(f"[yellow]{desc}[/yellow]:\n{out}\n")

if __name__ == "__main__":
    main()
