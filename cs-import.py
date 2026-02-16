#!/usr/bin/env python3
"""
2026-02-16
CrowdSec Blocklist Importer (Python Version)
Auto-detect Native/Docker.
"""

import os
import sys
import subprocess
import logging
import ipaddress
import urllib.request
import urllib.error
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ROOT CHECK ---
if os.geteuid() != 0:
    print("Error: This script must be run as root (use sudo).", file=sys.stderr)
    sys.exit(1)

# --- CONFIGURATION ---
LOG_FILE = "/var/log/cs-import.log"
MIN_IPS = 200            # Safety brake
MAX_WORKERS = 10         # Parallel downloads
TIMEOUT = 15             # Seconds per request
RETRIES = 3
DECISION_DURATION = "24h"
CROWDSEC_CONTAINER = "crowdsec" # Name of container if using Docker
IMPORT_ORIGIN = "cscli-import"  # The origin assigned automatically by cscli import

# Custom Whitelist
CUSTOM_WHITELIST = [
    "1.1.1.1", "8.8.8.8", "9.9.9.9", "::1",
    "2001:4860:4860::8888", "2606:4700:4700::1111"
]

# Blocklist Sources
BLOCKLISTS = [
    ("AbuseIPDB", "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4"),
    ("IPsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
    ("Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt"),
    ("Spamhaus EDROP", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/spamhaus_edrop.netset"),
    ("Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("URLhaus", "https://urlhaus.abuse.ch/downloads/text_online/"),
    ("CI Army", "https://cinsscore.com/list/ci-badguys.txt"),
    ("Clean talk", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cleantalk_1d.ipset"),
    ("Binary Defense", "https://www.binarydefense.com/banlist.txt"),
    ("Bruteforce Blocker", "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"),
    ("Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist"),
    ("Blocklist.de All", "https://lists.blocklist.de/lists/all.txt"),
    ("Blocklist.de SSH", "https://lists.blocklist.de/lists/ssh.txt"),
    ("Blocklist.de Apache", "https://lists.blocklist.de/lists/apache.txt"),
    ("Blocklist.de Mail", "https://lists.blocklist.de/lists/mail.txt"),
    ("GreenSnow", "https://blocklist.greensnow.co/greensnow.txt"),
    ("DShield", "https://feeds.dshield.org/block.txt"),
    ("Botscout", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/botscout_7d.ipset"),
    ("Firehol L1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
    ("Firehol L2", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"),
    ("Firehol L3", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_level3.netset"),
    ("Firehol Webclient", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_webclient.netset"),
    ("MyIP.ms", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/myip.ipset"),
    ("SOCKS Proxies", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/socks_proxy_7d.ipset"),
    ("Botvrij", "https://www.botvrij.eu/data/ioclist.ip-dst.raw"),
    ("StopForumSpam", "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt"),
    ("Shodan Scanners", "https://gist.githubusercontent.com/jfqd/4ff7fa70950626a11832a4bc39451c1c/raw"),
    ("PHP Spammers", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/php_spammers_7d.ipset"),
    ("Spamhaus DROPv6", "https://www.spamhaus.org/drop/dropv6.txt"),
    ("list.rtbh.com.tr", "https://list.rtbh.com.tr/output.txt"),
]

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)])
log = logging.getLogger()

# --- HELPER FUNCTIONS ---
def fetch_url(name, url):
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Blocklist-Updater/3.0'})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                if response.status == 200: return response.read().decode('utf-8', errors='ignore')
        except Exception: time.sleep(1)
    log.warning(f"{name}: Failed download.")
    return None

def is_safe_ip(net):
    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved: return False
    if isinstance(net, ipaddress.IPv4Network) and str(net).startswith('0.'): return False
    return True

def parse_ips(name, text):
    valid_nets = set()
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for line in text.splitlines():
        line = line.strip().split('#')[0].split(';')[0].strip()
        if not line: continue
        net = None
        if name == "DShield":
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                try: net = ipaddress.ip_network(f"{parts[0]}/{parts[2]}", strict=False)
                except ValueError: pass
        if net is None:
            try: net = ipaddress.ip_network(line.split()[0], strict=False)
            except ValueError:
                match = ipv4_pattern.search(line)
                if match:
                    try: net = ipaddress.ip_network(match.group(), strict=False)
                    except ValueError: pass
        if net and is_safe_ip(net): valid_nets.add(net)
    return valid_nets

def get_blocklists():
    all_nets = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_name = {executor.submit(fetch_url, name, url): name for name, url in BLOCKLISTS}
        for future in as_completed(future_to_name):
            content = future.result()
            if content:
                nets = parse_ips(future_to_name[future], content)
                if nets:
                    log.info(f"{future_to_name[future]}: {len(nets)}")
                    all_nets.extend(nets)
    return all_nets

def optimize_and_filter(networks, whitelist):
    v4_nets = [n for n in networks if n.version == 4]
    v6_nets = [n for n in networks if n.version == 6]
    wl_v4 = [ipaddress.ip_network(w, strict=False) for w in whitelist if ipaddress.ip_network(w, strict=False).version == 4]
    wl_v6 = [ipaddress.ip_network(w, strict=False) for w in whitelist if ipaddress.ip_network(w, strict=False).version == 6]

    def process(nets, wl):
        if not nets: return []
        nets = list(ipaddress.collapse_addresses(nets))
        clean = []
        for net in nets:
            candidates = [net]
            for w in wl:
                new_cand = []
                for c in candidates:
                    if not c.overlaps(w): new_cand.append(c); continue
                    if w.supernet_of(c) or w == c: continue
                    try: new_cand.extend(c.address_exclude(w))
                    except ValueError: pass
                candidates = new_cand
                if not candidates: break
            clean.extend(candidates)
        return list(ipaddress.collapse_addresses(clean))

    return process(v4_nets, wl_v4) + process(v6_nets, wl_v6)

# --- CROWDSEC LOGIC ---
def detect_mode():
    """Robustly checks for cscli or Docker, handling missing commands."""
    try:
        if subprocess.run(["cscli", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            log.info("Mode: Native (cscli found)")
            return "native"
    except FileNotFoundError: pass

    try:
        if subprocess.run(["docker", "ps", "-q", "-f", f"name=^{CROWDSEC_CONTAINER}$"], stdout=subprocess.DEVNULL).returncode == 0:
            log.info(f"Mode: Docker (container: {CROWDSEC_CONTAINER})")
            return "docker"
    except FileNotFoundError: pass

    log.error("Could not detect CrowdSec (neither 'cscli' nor Docker container found).")
    sys.exit(1)

def check_lapi_health(mode):
    """Pre-flight check to ensure CrowdSec LAPI is reachable via standard status check."""
    cmd = ["cscli", "lapi", "status"]
    if mode == "docker": cmd = ["docker", "exec", CROWDSEC_CONTAINER] + cmd

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        log.error("CrowdSec LAPI is not ready (cscli lapi status failed). Aborting.")
        sys.exit(1)

def flush_old_decisions(mode):
    """Removes all previous blocklist decisions."""
    log.info(f"Flushing old decisions (Origin: {IMPORT_ORIGIN})...")
    cmd = ["cscli", "decisions", "delete", "--origin", IMPORT_ORIGIN]
    if mode == "docker": cmd = ["docker", "exec", CROWDSEC_CONTAINER] + cmd

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0: log.info("✓ Flush successful.")
        else: log.warning(f"Flush warning: {res.stderr.strip()}")
    except Exception as e: log.error(f"Error flushing: {e}")

def import_decisions(mode, new_nets):
    if not new_nets: return
    log.info(f"Importing {len(new_nets)} new decisions...")

    flags = [
        "--format", "values",
        "--duration", DECISION_DURATION,
        "--reason", "external_blocklist",
        "--type", "ban",
        "--batch", "1000"
    ]

    cmd = ["cscli", "decisions", "import", "-i", "-"] + flags
    if mode == "docker": cmd = ["docker", "exec", "-i", CROWDSEC_CONTAINER, "cscli", "decisions", "import", "-i", "-"] + flags

    try:
        res = subprocess.run(cmd, input="\n".join(str(n) for n in new_nets), text=True, capture_output=True)
        if res.returncode == 0: log.info("✓ Import successful.")
        else: log.error(f"Import failed: {res.stderr}")
    except Exception as e: log.error(f"Error: {e}")

# --- LOCKING ---
def acquire_lock():
    lock_file = "/tmp/cs-import.lock"
    if os.path.exists(lock_file):
        try:
            with open(lock_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            log.error(f"Script already running (PID {pid}). Exiting.")
            sys.exit(1)
        except (OSError, ValueError):
            log.warning("Found stale lock file. Removing.")
            os.remove(lock_file)
    with open(lock_file, 'w') as f: f.write(str(os.getpid()))

def release_lock():
    if os.path.exists("/tmp/cs-import.lock"): os.remove("/tmp/cs-import.lock")

def main():
    acquire_lock()
    try:
        mode = detect_mode()
        check_lapi_health(mode)

        log.info("Starting blocklist download...")
        raw = get_blocklists()
        if not raw: sys.exit(1)

        log.info("Optimizing...")
        clean = optimize_and_filter(raw, CUSTOM_WHITELIST)
        if len(clean) < MIN_IPS: log.error("Safety brake triggered (Too few IPs)."); sys.exit(1)

        flush_old_decisions(mode)
        import_decisions(mode, clean)

    finally:
        release_lock()

if __name__ == "__main__":
    main()
