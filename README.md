# recon-pipeline

An automated web reconnaissance pipeline that chains **subfinder → httpx → gowitness → feroxbuster → nmap → nuclei** into a single command, and outputs one structured report (JSON + Markdown) joining every tool's findings by host.

Built to replace the manual "run six tools, cross-reference the output by hand" workflow with one command and one report — the same recon chain used to find real findings during my own DVWA / OWASP Juice Shop / TryHackMe practice (see [my pentest report](#) and [writeups](#) for the manual version of this same workflow).

## What it does

```
domain / single host
       |
       v
[1] subfinder      -> enumerate subdomains (skipped in single-target mode)
       |
       v
[2] httpx          -> check which hosts are live, grab status/title/tech/IP
       |
       v
[3] gowitness      -> screenshot every live host
       |
       v
[4] feroxbuster    -> directory/content discovery on each live host
       |
       v
[5] nmap           -> port-scan every unique IP (concurrent, deduplicated)
       |
       v
[6] nuclei         -> vulnerability scan against every live URL
       |
       v
   report.json + report.md -- every finding joined by host
```

Each stage's output is independently valid JSON/JSONL on disk, so the pipeline survives partial failures -- if nuclei times out on one target, everything gathered by the previous stages is still there and still usable.

## Sample output

```markdown
### http://127.0.0.1
- **Status:** 302  |  **Title:** (none)
- **Tech:** Apache HTTP Server:2.4.25, Debian, PHP
- **IP:** 127.0.0.1
- **Open ports:** 22/tcp (ssh - OpenSSH), 80/tcp (http - Apache httpd)
- **Screenshot:** screenshots/http---127.0.0.1-80.jpeg
- **Discovered paths:**
  - [301] http://127.0.0.1/config
  - [200] http://127.0.0.1/php.ini
  - [200] http://127.0.0.1/robots.txt
  - [302] http://127.0.0.1/phpinfo.php
- **Vulnerabilities:**
  - [MEDIUM] Sensitive Configuration Files Listing - Detect -- http://127.0.0.1/config/
```

The /config/ vulnerability and the /php.ini exposure each took a full manual pentest session to find the first time (command injection -> filesystem enumeration -> config file discovery). This pipeline surfaces both automatically, in one run.

## Install

Requires Go tools on $PATH (or $GOPATH/bin) and Python 3 -- no pip dependencies, the script only uses the standard library.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
sudo apt install nmap nuclei feroxbuster -y   # Kali/Debian

nuclei -update-templates   # required once before first use
```

## Usage

Enumerate a domain's subdomains and scan all live hosts:
```bash
python3 recon.py -d example.com
```

Scan one already-known host directly (skips subdomain enumeration):
```bash
python3 recon.py -t http://127.0.0.1
```

Passive only -- never sends active traffic, no prompt:
```bash
python3 recon.py -d example.com --passive
```

Scripted/CI use -- auto-confirms all active-recon prompts:
```bash
python3 recon.py -d example.com --yes
```

### Flags

| Flag | Description |
|---|---|
| `-d, --domain` | Domain to enumerate subdomains for |
| `-t, --target` | Single known host/URL -- skips subfinder |
| `-o, --output` | Output directory (default: output) |
| `--passive` | Skip feroxbuster, nmap and nuclei entirely, no active traffic |
| `--yes` | Auto-confirm all active-recon authorization prompts |
| `--max-hosts` | Abort before active stages if live host count exceeds this (default: 200) |

Exactly one of -d / -t is required.

## Safety by design

- **Active-recon confirmation gate** -- feroxbuster, nmap, and nuclei each require an explicit y before running (or --yes for scripted use). Subfinder/httpx/gowitness are treated as low-risk recon; the three active stages are gated separately since a target's scope may permit one but not the others.
- **--passive mode** for out-of-scope targets -- guarantees zero active traffic, no prompt shown at all.
- **dos/fuzz nuclei templates excluded by default** -- this tool detects, it does not attempt to disrupt a service.
- **--max-hosts cap** -- prevents an unexpectedly large domain from turning a quick recon run into an hours-long scan.

Only run this against targets you own or are explicitly authorized to test (e.g. an in-scope bug bounty program, or your own lab like DVWA/Juice Shop).

## Output structure

```
output/<target>_<timestamp>/
+-- subdomains.txt
+-- live_hosts.jsonl              # structured httpx results
+-- live_hosts.txt                # human-readable httpx summary
+-- live_urls.txt                 # clean URL list, feeds gowitness/nuclei
+-- screenshots/                  # one .jpeg per live host
+-- gowitness.jsonl
+-- feroxbuster/
|   +-- <host>.jsonl              # raw feroxbuster output per host
|   +-- feroxbuster_summary.json  # parsed: discovered paths per host
+-- nmap/
|   +-- <ip>.xml                  # raw nmap XML per unique IP
|   +-- nmap_summary.json         # parsed: ip -> open ports/services
+-- nuclei.jsonl
+-- nuclei_summary.json
+-- report.json                   # everything joined, machine-readable
+-- report.md                     # everything joined, human-readable
```

## Design notes

- **Every tool call resolves its own binary path explicitly** rather than trusting $PATH -- this project's first real bug was a Python httpx pip package silently shadowing ProjectDiscovery's Go httpx binary of the same name. resolve_tool() checks $GOPATH/bin first, verifies the right tool actually responds where there's real collision risk, and falls back to PATH otherwise.
- **httpx, feroxbuster, and nuclei are parsed from their native JSON output**, not human-readable text -- an early version regex-parsed httpx's bracketed text output and silently corrupted any line with an empty field (e.g. no page title). Structured output removed that entire bug class. feroxbuster's JSONL mixes three record types (configuration, statistics, response) in one file; the parser filters strictly on type == "response" before extracting any fields, which the schema check before building the integration revealed.
- **nmap runs concurrently** (ThreadPoolExecutor, 5 workers) since each scan is I/O-bound, with results deduplicated by IP first -- several subdomains sharing one IP (common with CDNs) only get scanned once.
- **Every stage fails gracefully** -- missing binaries, empty inputs, scan timeouts, and corrupted XML output are all handled without taking down the rest of the pipeline.
- **404/400/500 responses filtered from feroxbuster output** -- feroxbuster auto-filters most 404-like responses during scanning, but a small number slip through; these are dropped at parse time so the report only surfaces actionable paths.

## Limitations / not done yet

- No rate-limiting beyond nuclei's and feroxbuster's built-in behavior -- reasonable for a handful of hosts, would need tuning for very large scopes.
- Screenshot-to-host matching (gowitness) uses a URL prefix fallback that could mismatch on unusual port/path combinations -- not hit in testing so far, but a known edge case.
- Single Python process -- stages run sequentially except nmap; a future version could pipeline stages across hosts instead of running each stage to completion before the next starts.
- feroxbuster wordlist path is currently hardcoded to Kali's default /usr/share/wordlists/dirb/common.txt -- a --wordlist flag would make this portable across distros.

## Why I built this

Built as part of hands-on penetration testing practice (see [pentest report](#) covering DVWA / OWASP Juice Shop / TryHackMe manual findings). This tool automates the recon phase of that same workflow -- the goal was to understand why each piece works (subprocess safety, JSON vs. text parsing, concurrency, authorization boundaries) well enough to debug it from scratch, not just chain some CLI tools together.
