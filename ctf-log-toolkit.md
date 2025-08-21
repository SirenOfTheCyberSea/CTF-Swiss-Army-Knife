# CTF Log Analysis Toolkit — Install & Usage Cheat Sheet

> Fast setup + copy‑paste commands for common CTF log challenges. Focus is Linux/macOS. Windows notes are included where helpful.

---

## 0) Quick Environment Setup

### Debian/Ubuntu
```bash
sudo apt update && sudo apt install -y \
  ripgrep jq lnav goaccess tshark zeek python3-pip python3-venv \
  git sqlite3 unzip
# Allow non-root capture for tshark (optional)
sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark "$USER"
```

### macOS (Homebrew)
```bash
# Install Homebrew if needed: https://brew.sh
brew update && brew install ripgrep jq lnav goaccess wireshark zeek git sqlite unzip python
# Allow tshark capture (you may need to grant permissions)
```

### Python virtual env (recommended for Python tools)
```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
```

---

## 1) Core CLI Power-Ups

### ripgrep (rg) — ultrafast search
```bash
# Case-insensitive search for "flag" in all files
rg -i "flag\{.*\}" -n

# Show context around matches
rg -i "error|fail|unauth" -n --context 3 logs/

# Regex on IPs + count unique
rg -o --pcre2 '(?:\d{1,3}\.){3}\d{1,3}' access.log | sort | uniq -c | sort -nr | head
```

### jq — JSON log parsing
```bash
# Pretty print JSON
jq . file.json

# Filter Suricata eve.json for HTTP hosts
jq -r 'select(.event_type=="http") | .http.hostname' eve.json | sort -u

# Time-window filter (ISO8601)
jq 'select(.timestamp>="2025-08-20T00:00:00Z" and .timestamp<"2025-08-21T00:00:00Z")' file.json
```

### lnav — smart log viewer with SQL
```bash
# Auto-detect formats; open multiple logs
lnav /var/log/*.log access*.log

# In lnav (press ;) run SQL to count by status
;SELECT c_status, COUNT(*) AS n FROM access_log GROUP BY c_status ORDER BY n DESC;
```

### GoAccess — instant web log dashboard
```bash
# Nginx/Apache access log to terminal report
goaccess access.log --log-format=COMBINED --utc -o report.html
# Open report.html in browser for interactive view
```

---

## 2) Web/HTTP Logs (Apache/Nginx)

```bash
# Top talkers
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head

# Suspicious URLs (LFI/RFI/SQLi patterns)
rg -n "(\.\./|/etc/passwd|union.*select|concat\(|load_file\()" access.log

# Uncommon user agents
awk -F\" '{print $6}' access.log | sort | uniq -c | sort -nr | head

# Timeline by minute
awk '{print $4}' access.log | cut -d: -f1-2 | sort | uniq -c | sort -nr | head
```

---

## 3) Windows Event Logs (EVTX)

### Chainsaw (Sigma hunting, EVTX fast scan)
```bash
# Install (Linux/macOS)
mkdir -p tools && cd tools
# Prebuilt releases: https://github.com/WithSecureLabs/chainsaw/releases
# Example (Linux x64):
curl -L -o chainsaw.zip https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-unknown-linux-gnu.zip
unzip chainsaw.zip && chmod +x chainsaw && cd ..

# Run against a directory of EVTX with default Sigma rules
./tools/chainsaw hunt /path/to/evtx --rules ./tools/rules --json results.json
# Quick suspicious events by timeframe
./tools/chainsaw search /path/to/evtx --from "2025-08-20 00:00:00" --to "2025-08-21 00:00:00" -s "EventID:4688 AND powershell"
```

**Sigma rules** (optional rule pack):
```bash
# Download a public Sigma ruleset
git clone https://github.com/SigmaHQ/sigma.git tools/sigmahq
# Use with Chainsaw
./tools/chainsaw hunt /path/to/evtx --rules tools/sigmahq/rules --json results.json
```

### DeepBlueCLI (PowerShell-based Windows log triage)
```powershell
# Windows PowerShell (Run as admin)
git clone https://github.com/sans-blue-team/DeepBlueCLI.git
cd DeepBlueCLI
powershell.exe -ExecutionPolicy Bypass -File .\DeepBlue.ps1 -LogPath C:\path\to\Security.evtx
```

### Convert EVTX → JSON/CSV (Linux)
```bash
# Install evtx_dump via pip
pip install evtx_dump evtx
# Dump to JSON for jq
evtx_dump /path/to/*.evtx > evtx.json
jq -r '.record.Event.System.EventID' evtx.json | sort | uniq -c | sort -nr | head
```

---

## 4) Network-Derived Logs & PCAP Adjacent

### Zeek — turn PCAPs into rich logs
```bash
zeek -r capture.pcap
# Inspect conn.log / http.log / dns.log, etc.
cut -f 5 -d$'\t' http.log | sort | uniq -c | sort -nr | head  # hosts
```

### tshark — quick features from PCAP
```bash
# HTTP hosts
tshark -r capture.pcap -Y http.host -T fields -e http.host | sort -u

# DNS queries
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u

# Export HTTP objects
tshark -r capture.pcap --export-objects "http,extracted/"
```

---

## 5) Timeline & Forensic Correlation

### Plaso (log2timeline) → Timesketch CSV
```bash
# Install (may take a while)
pip install plaso
# Create super timeline from a directory
log2timeline.py timeline.plaso /mnt/evidence/
# Convert to CSV for local triage
psort.py -o l2tcsv timeline.plaso > timeline.csv

# Quick local pivoting with sqlite (optional)
csvcut -n timeline.csv  # inspect columns (requires csvkit)
csvgrep -c message -m powershell timeline.csv | head
```

### Timesketch (optional, heavy)
- If the CTF provides Timesketch, upload `timeline.csv` and pivot by time ranges, usernames, hosts, or keywords.

---

## 6) Suricata / IDS Logs (eve.json)

```bash
# Top signatures
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -nr | head

# HTTP paths that triggered alerts
jq -r 'select(.event_type=="alert" and .http.uri) | .http.uri' eve.json | sort -u

# Correlate by src_ip → dest_ip
jq -r 'select(.src_ip and .dest_ip) | "\(.src_ip) -> \(.dest_ip)"' eve.json | sort | uniq -c | sort -nr | head
```

---

## 7) “Tell Me the Story” — Fast Playbook

1. **Identify format**: `file access.log`, `head -n 5`, `jq . | head`, `evtx_dump` sample.
2. **Triage**:
   - Web logs → `goaccess`, `lnav`, `rg` patterns.
   - EVTX → `chainsaw` default hunt, then refine with Sigma and `jq`/`evtx_dump`.
   - PCAP → `zeek` to logs, then pivot `conn.log`, `http.log`.
   - JSON/Suricata → `jq` filters.
3. **Pivot** by IPs, users, URIs, parent/child processes, time windows.
4. **Prove the narrative**: Extract concrete artifacts (hashes, URLs, exact timestamps) for the flag.
5. **Search for flags**: `rg -i "flag\{|CTF{|FLAG{" -n` (and variations).

---

## 8) One-Liners You’ll Reuse

```bash
# Unique IPs with counts (works on many log types)
rg -o --pcre2 '(?:\d{1,3}\.){3}\d{1,3}' * | awk '{print $1}' | sort | uniq -c | sort -nr | head

# Extract base64-like blobs for decoding
rg -o --pcre2 '[A-Za-z0-9+/]{20,}={0,2}' *.log | sort -u > b64.txt

# Find URLs
rg -o --pcre2 'https?://[^\s"]+' * | sort -u > urls.txt

# ISO8601 time range filter (jq)
jq 'select(.timestamp>="2025-01-01T00:00:00Z" and .timestamp<"2025-12-31T00:00:00Z")' file.json

# Top user agents from combined log
awk -F\" '{print $6}' access.log | sort | uniq -c | sort -nr | head
```

---

## 9) Windows-Only Notes

- **DeepBlueCLI** is easiest on Windows PowerShell.
- **Chainsaw** has Windows binaries; run `chainsaw.exe hunt C:\EVTX\ --rules C:\rules\`.
- For CSV/JSON pivoting: use **CMTrace**, **Event Log Explorer**, or **Timeline Explorer**.

---

## 10) Nice-to-Have GUI Tools

- **CyberChef (web)**: https://gchq.github.io/CyberChef/
- **Klogg/glogg**: huge-file GUI log viewers.
- **Splunk Free / Elastic Kibana**: if allowed in the CTF VM, can accelerate dashboards.

---

### Credits/Notes
- Many tools are open-source. Always check challenge rules for internet access/install allowances.
- Consider bundling a USB or VM with preinstalled binaries for offline CTF environments.
