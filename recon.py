#!/usr/bin/env python3
import argparse
import subprocess
import shutil
import json
import re
import xml.etree.ElementTree as ET
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_tool(name, verify_string=None):
    """
    Find a tool's real binary path, checking Go's install dir first,
    then falling back to PATH. If verify_string is given, run `-version`
    and confirm the expected tool actually responds (guards against
    name collisions like the Python httpx package shadowing the Go one).
    """
    gobin_result = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True)
    gopath = gobin_result.stdout.strip()
    candidates = []
    if gopath:
        candidates.append(os.path.join(gopath, "bin", name))
    which_result = shutil.which(name)
    if which_result:
        candidates.append(which_result)

    for path in candidates:
        if path and os.path.isfile(path):
            if verify_string:
                try:
                    check = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)
                    combined = (check.stdout + check.stderr).lower()
                    if verify_string.lower() not in combined:
                        continue  # wrong tool with the same name — keep looking
                except Exception:
                    continue
            return path
    return None


# Resolve every tool once, at startup, with verification only where there's
# a real collision risk (httpx). subfinder/gowitness/nmap have no competing
# same-named tool on this system, so a plain existence check is enough.
SUBFINDER_BIN = resolve_tool("subfinder", verify_string="subfinder")
HTTPX_BIN = resolve_tool("httpx", verify_string="projectdiscovery")
GOWITNESS_BIN = resolve_tool("gowitness")
NMAP_BIN = shutil.which("nmap")
NUCLEI_BIN = shutil.which("nuclei")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated recon pipeline: subfinder -> httpx -> gowitness -> nmap"
    )
    parser.add_argument("-d", "--domain", help="Target domain to enumerate subdomains for (e.g. example.com)")
    parser.add_argument("-t", "--target", help="Single already-known host/URL to scan directly — skips subfinder entirely (e.g. http://127.0.0.1, or a single IP/hostname)")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    parser.add_argument("--passive", action="store_true",
                         help="Skip active stages (nmap, nuclei) entirely — no prompt, no active traffic sent")
    parser.add_argument("--yes", action="store_true",
                         help="Auto-confirm the active-recon prompt (for scripted/automated runs)")
    parser.add_argument("--max-hosts", type=int, default=200,
                         help="Safety cap: abort before nmap/gowitness/nuclei if more than this many live hosts are found (default: 200). Prevents an unexpectedly large domain from turning a quick recon run into an hours-long scan.")
    args = parser.parse_args()
    if bool(args.domain) == bool(args.target):
        parser.error("specify exactly one of -d/--domain (enumerate a domain) or -t/--target (scan one known host)")
    return args


def confirm_active_recon(stage_name, auto_yes=False):
    """
    Gate an active-recon stage behind explicit confirmation. Returns True if
    the stage should run. --passive skips this function entirely (checked by
    the caller); this only handles the interactive yes/no when --passive
    wasn't set. Defaults to 'no' on empty input or non-interactive stdin —
    silence should never be read as authorization.
    """
    if auto_yes:
        print(f"[*] {stage_name}: active recon auto-confirmed (--yes)")
        return True
    try:
        answer = input(
            f"[?] {stage_name} sends live traffic designed to probe/detect vulnerabilities "
            f"against the target. Are you authorized to run active recon here? [y/N]: "
        ).strip().lower()
    except EOFError:
        answer = ""  # non-interactive stdin (e.g. piped/cron) — treat as "no"
    confirmed = answer == "y"
    if not confirmed:
        print(f"[!] {stage_name} skipped — not confirmed")
    return confirmed


def run_command(command, timeout=300):
    """Run an external tool safely and return its stdout as text."""
    tool_path = command[0]
    if not tool_path or not os.path.isfile(tool_path):
        print(f"[!] Binary not found or not resolved: {tool_path}")
        return ""
    print(f"[*] Running: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 and result.stderr:
            print(f"[!] {os.path.basename(tool_path)} stderr: {result.stderr.strip()[:200]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] Timed out after {timeout}s: {' '.join(command)}")
        return ""


def run_subfinder(domain, run_dir):
    output_file = os.path.join(run_dir, "subdomains.txt")
    output = run_command([SUBFINDER_BIN, "-d", domain, "-silent"])
    subdomains = sorted(set(line.strip() for line in output.splitlines() if line.strip()))

    with open(output_file, "w") as f:
        f.write("\n".join(subdomains))

    print(f"[+] {len(subdomains)} subdomains found -> {output_file}")
    return subdomains


def run_httpx(subdomains, run_dir):
    """
    Probe subdomains with httpx using -json for real structured output
    (status_code as int, tech as a list) instead of parsing the bracketed
    text format, which silently breaks when a field like title is empty.
    """
    jsonl_file = os.path.join(run_dir, "live_hosts.jsonl")
    summary_file = os.path.join(run_dir, "live_hosts.txt")
    urls_file = os.path.join(run_dir, "live_urls.txt")

    if not subdomains:
        print("[!] No subdomains to probe — skipping httpx")
        for f in (jsonl_file, summary_file, urls_file):
            open(f, "w").close()
        return []

    input_file = os.path.join(run_dir, "subdomains.txt")
    output = run_command([
        HTTPX_BIN, "-l", input_file, "-silent",
        "-status-code", "-title", "-tech-detect", "-json"
    ], timeout=180)

    parsed_hosts = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue  # skip log/banner noise (e.g. first-run model download messages)
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_hosts.append({
            "url": record.get("url", ""),
            "status_code": record.get("status_code", ""),
            "title": record.get("title", ""),
            "tech": record.get("tech", []),
            "webserver": record.get("webserver", ""),
            "host_ip": record.get("host_ip", ""),
        })

    with open(jsonl_file, "w") as f:
        for h in parsed_hosts:
            f.write(json.dumps(h) + "\n")

    with open(summary_file, "w") as f:
        for h in parsed_hosts:
            f.write(f"{h['url']} [{h['status_code']}] [{h['title']}] [{','.join(h['tech'])}]\n")

    with open(urls_file, "w") as f:
        f.write("\n".join(h["url"] for h in parsed_hosts))

    print(f"[+] {len(parsed_hosts)} live hosts -> {jsonl_file}")
    return parsed_hosts


def run_gowitness(run_dir):
    urls_file = os.path.join(run_dir, "live_urls.txt")
    screenshot_dir = os.path.join(run_dir, "screenshots")
    jsonl_file = os.path.join(run_dir, "gowitness.jsonl")
    os.makedirs(screenshot_dir, exist_ok=True)

    if not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
        print("[!] No live URLs to screenshot — skipping gowitness")
        return jsonl_file

    run_command([
        GOWITNESS_BIN, "scan", "file",
        "-f", urls_file,
        "-s", screenshot_dir,
        "--write-jsonl",
        "--write-jsonl-file", jsonl_file,
    ], timeout=600)  # screenshotting is slow — give it real headroom

    print(f"[+] Screenshots -> {screenshot_dir}")
    print(f"[+] JSONL results -> {jsonl_file}")
    return jsonl_file


def parse_nmap_xml(xml_file):
    """Extract ip + open ports/services from one nmap XML output file."""
    if not os.path.isfile(xml_file):
        return None

    try:
        tree = ET.parse(xml_file)
    except ET.ParseError:
        # A timed-out or killed nmap process can leave a truncated/invalid
        # XML file behind. One bad host shouldn't take down the whole run.
        print(f"[!] Corrupt/incomplete nmap XML, skipping: {xml_file}")
        return None

    root = tree.getroot()

    host_elem = root.find("host")
    if host_elem is None:
        return None  # host was down / scan produced no host block

    ip = host_elem.find("address").get("addr")

    ports = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state = port_elem.find("state").get("state")
            if state != "open":
                continue  # skip filtered/closed — we only care about open ports
            service_elem = port_elem.find("service")
            ports.append({
                "port": int(port_elem.get("portid")),
                "protocol": port_elem.get("protocol"),
                "service": service_elem.get("name") if service_elem is not None else "",
                "product": service_elem.get("product", "") if service_elem is not None else "",
            })

    return {"ip": ip, "open_ports": ports}


def _scan_one_ip(ip, nmap_dir):
    """Run nmap against a single IP and return its parsed result (or None). Designed to be called from a thread pool — each call is fully independent (own subprocess, own output file)."""
    safe_name = ip.replace(":", "_")  # IPv6-safe filename
    xml_out = os.path.join(nmap_dir, f"{safe_name}.xml")
    run_command([
        NMAP_BIN, "-sV", "-T4", "--top-ports", "100",
        "-oX", xml_out,
        ip
    ], timeout=180)
    return parse_nmap_xml(xml_out)


def run_nmap(live_hosts, run_dir, max_workers=5):
    """
    Port-scan each live host's unique IP concurrently. Each nmap call is I/O-bound
    (mostly waiting on network responses), so a thread pool gives a real speedup
    without the complexity of multiprocessing — we're not CPU-bound here.
    max_workers is capped at 5 by default: fast enough to matter, but not so
    aggressive it looks like a burst/DoS against the target's IDS.
    """
    nmap_dir = os.path.join(run_dir, "nmap")
    os.makedirs(nmap_dir, exist_ok=True)

    seen_ips = set()  # multiple subdomains often share one IP — don't scan the same IP twice
    unique_ips = []
    for host in live_hosts:
        ip = host.get("host_ip", "")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.append(ip)

    results = []
    if unique_ips:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_ip = {pool.submit(_scan_one_ip, ip, nmap_dir): ip for ip in unique_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    parsed = future.result()
                except Exception as e:
                    print(f"[!] nmap failed for {ip}: {e}")
                    parsed = None
                if parsed:
                    results.append(parsed)

    nmap_json = os.path.join(nmap_dir, "nmap_summary.json")
    with open(nmap_json, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] nmap scanned {len(results)} unique IPs -> {nmap_json}")
    return results



def build_report(domain, run_dir, subdomains, live_hosts, gowitness_jsonl, nmap_results, nuclei_findings):
    """
    Join subfinder + httpx + gowitness + nmap + nuclei results into one report.
    Joins are by shared key: httpx<->nmap on IP, httpx<->gowitness on URL,
    httpx<->nuclei on URL prefix (nuclei's matched-at often includes a path).
    """
    nmap_by_ip = {r["ip"]: r["open_ports"] for r in nmap_results}

    screenshots_by_url = {}
    if os.path.isfile(gowitness_jsonl):
        with open(gowitness_jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                screenshots_by_url[record.get("url", "")] = record.get("file_name", "")

    combined_hosts = []
    for host in live_hosts:
        ip = host.get("host_ip", "")
        url = host.get("url", "")

        screenshot = screenshots_by_url.get(url, "")
        if not screenshot:
            for gw_url, fname in screenshots_by_url.items():
                if gw_url.startswith(url):
                    screenshot = fname
                    break

        # a host "owns" a nuclei finding if its base URL is a prefix of matched-at
        host_vulns = [f for f in nuclei_findings if f.get("matched_at", "").startswith(url)]

        combined_hosts.append({
            "url": url,
            "status_code": host.get("status_code", ""),
            "title": host.get("title", ""),
            "tech": host.get("tech", []),
            "host_ip": ip,
            "open_ports": nmap_by_ip.get(ip, []),
            "screenshot": screenshot,
            "vulnerabilities": host_vulns,
        })

    report = {
        "domain": domain,
        "generated_at": datetime.now().isoformat(),
        "total_subdomains": len(subdomains),
        "total_live_hosts": len(live_hosts),
        "total_vulnerabilities": len(nuclei_findings),
        "hosts": combined_hosts,
    }

    json_path = os.path.join(run_dir, "report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = os.path.join(run_dir, "report.md")
    lines = [
        f"# Recon Report — {domain}",
        f"*Generated: {report['generated_at']}*",
        "",
        f"- **Subdomains found:** {report['total_subdomains']}",
        f"- **Live hosts:** {report['total_live_hosts']}",
        f"- **Vulnerabilities (medium+):** {report['total_vulnerabilities']}",
        "",
        "## Hosts",
        "",
    ]
    for h in combined_hosts:
        lines.append(f"### {h['url']}")
        lines.append(f"- **Status:** {h['status_code']}  |  **Title:** {h['title'] or '(none)'}")
        lines.append(f"- **Tech:** {', '.join(h['tech']) if h['tech'] else '(none detected)'}")
        lines.append(f"- **IP:** {h['host_ip'] or '(unresolved)'}")
        if h["open_ports"]:
            port_list = ", ".join(f"{p['port']}/{p['protocol']} ({p['service']}{' - ' + p['product'] if p['product'] else ''})" for p in h["open_ports"])
            lines.append(f"- **Open ports:** {port_list}")
        else:
            lines.append("- **Open ports:** none found / not scanned")
        if h["screenshot"]:
            lines.append(f"- **Screenshot:** `screenshots/{h['screenshot']}`")
        if h["vulnerabilities"]:
            lines.append("- **Vulnerabilities:**")
            for v in h["vulnerabilities"]:
                cve = f" ({v['cve_id']})" if v.get("cve_id") else ""
                lines.append(f"  - `[{v['severity'].upper()}]` {v['name']}{cve} — {v['matched_at']}")
        lines.append("")

    with open(md_path, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Report written -> {json_path}")
    print(f"[+] Report written -> {md_path}")
    return report

def run_nuclei(run_dir):
    """
    Scan all live URLs with nuclei's vulnerability templates.
    -or (omit-raw) strips the full request/response bodies from each finding —
    without it, the JSONL balloons in size and becomes unpleasant to parse/store.
    dos/fuzz tags are excluded since those templates actively try to disrupt
    a service rather than just detect something — not appropriate for a
    tool that might get pointed at a target by habit.
    """
    urls_file = os.path.join(run_dir, "live_urls.txt")
    jsonl_file = os.path.join(run_dir, "nuclei.jsonl")
    summary_file = os.path.join(run_dir, "nuclei_summary.json")

    if not NUCLEI_BIN or not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
        print("[!] No live URLs to scan, or nuclei not found — skipping nuclei")
        open(summary_file, "w").write("[]")
        return []

    run_command([
        NUCLEI_BIN, "-l", urls_file,
        "-s", "medium,high,critical",
        "-etags", "dos,fuzz",
        "-mt", "10m",
        "-or", "-j", "-o", jsonl_file,
        "-silent"
    ], timeout=650)

    findings = []
    if os.path.isfile(jsonl_file):
        with open(jsonl_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = record.get("info", {})
                findings.append({
                    "template_id": record.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", ""),
                    "cve_id": (info.get("classification") or {}).get("cve-id"),
                    "matched_at": record.get("matched-at", record.get("url", "")),
                    "description": (info.get("description") or "").strip(),
                })

    with open(summary_file, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"[+] nuclei found {len(findings)} medium+ findings -> {summary_file}")
    return findings


def main():
    args = parse_args()
    label = args.domain or args.target
    safe_label = re.sub(r'[^a-zA-Z0-9._-]', '_', label)  # target/URL can contain chars unsafe for a folder name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.output, f"{safe_label}_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    print(f"[*] Target        : {label} ({'domain enumeration' if args.domain else 'single target'})")
    print(f"[*] Output dir    : {run_dir}")
    print(f"[*] subfinder     : {SUBFINDER_BIN or 'NOT FOUND'}")
    print(f"[*] httpx         : {HTTPX_BIN or 'NOT FOUND'}")
    print(f"[*] gowitness     : {GOWITNESS_BIN or 'NOT FOUND'}")
    print(f"[*] nmap          : {NMAP_BIN or 'NOT FOUND'}")
    print(f"[*] nuclei        : {NUCLEI_BIN or 'NOT FOUND'}")

    if args.domain:
        subdomains = run_subfinder(args.domain, run_dir)
    else:
        # Single-target mode: skip subfinder entirely, seed the pipeline
        # with the one host the user already knows about (e.g. DVWA on
        # 127.0.0.1). httpx accepts a bare host or a full URL in its
        # input list, so this feeds cleanly into the exact same run_httpx
        # used for domain mode — no separate code path needed downstream.
        subdomains = [args.target]
        with open(os.path.join(run_dir, "subdomains.txt"), "w") as f:
            f.write(args.target)

    live_hosts = run_httpx(subdomains, run_dir)

    if len(live_hosts) > args.max_hosts:
        print(f"[!] {len(live_hosts)} live hosts found, which exceeds --max-hosts ({args.max_hosts}).")
        print(f"[!] Aborting before gowitness/nmap/nuclei to avoid an unexpectedly long scan.")
        print(f"[!] Re-run with a higher --max-hosts value if this is intentional.")
        return

    gowitness_jsonl = run_gowitness(run_dir)
    if args.passive:
        print("[*] --passive set: skipping nmap and nuclei, no active traffic will be sent")
        nmap_results, nuclei_findings = [], []
    else:
        nmap_results = run_nmap(live_hosts, run_dir) if confirm_active_recon("nmap (port scan)", args.yes) else []
        nuclei_findings = run_nuclei(run_dir) if confirm_active_recon("nuclei (vulnerability scan)", args.yes) else []

    report = build_report(label, run_dir, subdomains, live_hosts, gowitness_jsonl, nmap_results, nuclei_findings)

    print(f"\n[OK] Recon complete for {label}")
    print(f"[OK] {report['total_subdomains']} subdomains, {report['total_live_hosts']} live hosts")
    print(f"[OK] Full report: {run_dir}/report.md")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user — partial results (if any) are saved in the run's output directory.")
        raise SystemExit(130)  # 130 = standard exit code for SIGINT, useful if this is ever chained in a script
