#!/usr/bin/env python3
"""
2026-03-12
Fail2Ban/NFTables Blocklist Importer
Auto-detect NFTables. GitHub + Cloudflare whitelisted.
"""

import json
import os
import sys
import subprocess
import logging
import ipaddress
import urllib.request
import urllib.error
import time
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ROOT CHECK ---
if os.geteuid() != 0:
    print("Error: This script must be run as root (use sudo).", file=sys.stderr)
    sys.exit(1)

# --- CONFIGURATION ---
NFT_TABLE     = "import_blocklists"
LOG_FILE      = "/var/log/import-blocklists.log"
LOG_MAX_LINES = 2000
MIN_IPS       = 200
MAX_WORKERS   = 10
TIMEOUT       = 15
RETRIES       = 3

# --- LOGGING ---
def truncate_log_if_needed():
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        if len(lines) > LOG_MAX_LINES:
            with open(LOG_FILE, "w") as f:
                f.write(f"[Log truncated - kept last {LOG_MAX_LINES} lines]\n")
                f.writelines(lines[-LOG_MAX_LINES:])
    except Exception as e:
        print(f"Warning: Could not truncate log: {e}", file=sys.stderr)

truncate_log_if_needed()
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger()

# --- STATIC WHITELISTS ---
CUSTOM_WHITELIST = [
    "1.1.1.1", "8.8.8.8", "9.9.9.9", "::1",
    "2001:4860:4860::8888", "2606:4700:4700::1111",
]

CLOUDFLARE_STATIC = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# Last verified 2026-03-12 from api.github.com/meta
GITHUB_STATIC = [
    "140.82.112.0/20", "192.30.252.0/22", "185.199.108.0/22",
    "143.55.64.0/20",  "20.99.172.64/28", "135.234.59.224/28",
    "2a0a:a440::/29", "2606:50c0::/32",
]

# --- BLOCKLIST SOURCES ---
BLOCKLISTS = [
    ("AbuseIPDB",          "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4"),
    ("IPsum",              "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
    ("Spamhaus DROP",      "https://www.spamhaus.org/drop/drop.txt"),
    ("Spamhaus EDROP",     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/spamhaus_edrop.netset"),
    ("Emerging Threats",   "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("Feodo Tracker",      "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("URLhaus",            "https://urlhaus.abuse.ch/downloads/text_online/"),
    ("CI Army",            "https://cinsscore.com/list/ci-badguys.txt"),
    ("Clean talk",         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cleantalk_1d.ipset"),
    ("Binary Defense",     "https://www.binarydefense.com/banlist.txt"),
    ("Bruteforce Blocker", "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"),
    ("Tor Exit Nodes",     "https://check.torproject.org/torbulkexitlist"),
    ("Blocklist.de All",   "https://lists.blocklist.de/lists/all.txt"),
    ("Blocklist.de SSH",   "https://lists.blocklist.de/lists/ssh.txt"),
    ("Blocklist.de Apache","https://lists.blocklist.de/lists/apache.txt"),
    ("Blocklist.de Mail",  "https://lists.blocklist.de/lists/mail.txt"),
    ("GreenSnow",          "https://blocklist.greensnow.co/greensnow.txt"),
    ("DShield",            "https://feeds.dshield.org/block.txt"),
    ("Botscout",           "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/botscout_7d.ipset"),
    ("Firehol L1",         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
    ("Firehol L2",         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"),
    ("Firehol L3",         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_level3.netset"),
    ("Firehol Webclient",  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_webclient.netset"),
    ("MyIP.ms",            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/myip.ipset"),
    ("SOCKS Proxies",      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/socks_proxy_7d.ipset"),
    ("Botvrij",            "https://www.botvrij.eu/data/ioclist.ip-dst.raw"),
    ("StopForumSpam",      "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt"),
    ("PHP Spammers",       "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/php_spammers_7d.ipset"),
    ("Spamhaus DROPv6",    "https://www.spamhaus.org/drop/dropv6.txt"),
    ("list.rtbh.com.tr",   "https://list.rtbh.com.tr/output.txt"),
]

# --- DYNAMIC WHITELIST ---
def fetch_dynamic_whitelist():
    """Fetch live IP ranges from GitHub and Cloudflare APIs, fall back to static lists."""
    ranges = []

    # GitHub
    try:
        req = urllib.request.Request(
            "https://api.github.com/meta",
            headers={"User-Agent": "Blocklist-Updater/3.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        seen = set()
        for key in ("hooks", "web", "git", "api"):
            for cidr in data.get(key, []):
                if cidr not in seen:
                    ranges.append(cidr)
                    seen.add(cidr)
        log.info(f"Dynamic whitelist: fetched {len(seen)} GitHub ranges from API")
        if len(seen) > 200:
            log.warning(f"GitHub whitelist unusually large ({len(seen)} ranges) - check API keys")
    except Exception as e:
        log.warning(f"Dynamic whitelist: GitHub API failed ({e}), using static fallback")
        ranges.extend(GITHUB_STATIC)

    # Cloudflare
    try:
        req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/ips",
            headers={"User-Agent": "Blocklist-Updater/3.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        cf_ranges = (
            data.get("result", {}).get("ipv4_cidrs", []) +
            data.get("result", {}).get("ipv6_cidrs", [])
        )
        if cf_ranges:
            ranges.extend(cf_ranges)
            log.info(f"Dynamic whitelist: fetched {len(cf_ranges)} Cloudflare ranges from API")
        else:
            raise ValueError("Empty result from Cloudflare API")
    except Exception as e:
        log.warning(f"Dynamic whitelist: Cloudflare API failed ({e}), using static fallback")
        ranges.extend(CLOUDFLARE_STATIC)

    return ranges

# --- HELPER FUNCTIONS ---
def fetch_url(name, url):
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Blocklist-Updater/3.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                if response.status == 200:
                    return response.read().decode("utf-8", errors="ignore")
        except Exception as e:
            if attempt == RETRIES - 1:
                log.warning(f"{name}: Failed after {RETRIES} retries. Error: {e}")
            else:
                time.sleep(1)
    return None

def is_safe_ip(net):
    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved:
        return False
    if isinstance(net, ipaddress.IPv4Network) and str(net).startswith("0."):
        return False
    return True

def parse_ips(name, text):
    valid_nets = set()
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for line in text.splitlines():
        line = line.strip().split("#")[0].split(";")[0].strip()
        if not line:
            continue
        net = None
        if name == "DShield":
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                try:
                    net = ipaddress.ip_network(f"{parts[0]}/{parts[2]}", strict=False)
                except ValueError:
                    pass
        if net is None:
            try:
                net = ipaddress.ip_network(line.split()[0], strict=False)
            except ValueError:
                match = ipv4_pattern.search(line)
                if match:
                    try:
                        net = ipaddress.ip_network(match.group(), strict=False)
                    except ValueError:
                        pass
        if net and is_safe_ip(net):
            valid_nets.add(net)
    return valid_nets

def get_blocklists():
    v4_list, v6_list = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_name = {executor.submit(fetch_url, name, url): name for name, url in BLOCKLISTS}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            content = future.result()
            if content:
                nets = parse_ips(name, content)
                if not nets:
                    log.warning(f"{name}: Downloaded but contained no valid IPs.")
                    continue
                log.info(f"{name}: {len(nets)}")
                for net in nets:
                    (v4_list if net.version == 4 else v6_list).append(net)
    return v4_list, v6_list

def optimize_and_filter(networks, whitelist):
    """Collapse overlapping subnets and carve out whitelisted ranges."""
    if not networks:
        return []
    networks = list(ipaddress.collapse_addresses(networks))
    wl_parsed = [ipaddress.ip_network(w, strict=False) for w in whitelist
                 if ipaddress.ip_network(w, strict=False).version == networks[0].version]
    clean = []
    for net in networks:
        candidates = [net]
        for w in wl_parsed:
            new_cand = []
            for c in candidates:
                if not c.overlaps(w):
                    new_cand.append(c)
                    continue
                if w.supernet_of(c) or w == c:
                    continue
                try:
                    new_cand.extend(c.address_exclude(w))
                except ValueError:
                    pass
            candidates = new_cand
            if not candidates:
                break
        clean.extend(candidates)
    return list(ipaddress.collapse_addresses(clean))

# --- NFTABLES ---
def apply_nftables(v4_nets, v6_nets):
    """Generate, validate, and atomically apply NFTables ruleset."""
    v4_str = ", ".join(str(n) for n in v4_nets)
    v6_str = ", ".join(str(n) for n in v6_nets)

    config = f"""
table inet {NFT_TABLE} {{
    set v4_list {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {v4_str} }}
    }}

    set v6_list {{
        type ipv6_addr
        flags interval
        auto-merge
        elements = {{ {v6_str} }}
    }}

    chain inbound {{
        type filter hook input priority -100; policy accept;
        ip saddr @v4_list counter drop
        ip6 saddr @v6_list counter drop
    }}
}}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as tmp:
        tmp.write(config)
        nft_path = tmp.name

    try:
        chk = subprocess.run(["nft", "-c", "-f", nft_path], capture_output=True, text=True)
        if chk.returncode != 0:
            log.error(f"NFTables syntax check failed: {chk.stderr.strip()}")
            return False

        subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], stderr=subprocess.DEVNULL)
        apply = subprocess.run(["nft", "-f", nft_path], capture_output=True, text=True)

        if apply.returncode == 0:
            log.info(f"✓ NFTables applied: {len(v4_nets)} IPv4 and {len(v6_nets)} IPv6 networks blocked.")
            return True
        else:
            log.error(f"Failed to apply NFTables rules: {apply.stderr.strip()}")
            return False
    finally:
        if os.path.exists(nft_path):
            os.remove(nft_path)

# --- LOCKING ---
def acquire_lock():
    lock_file = "/tmp/import-blocklists.lock"
    if os.path.exists(lock_file):
        try:
            with open(lock_file, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            log.error(f"Script already running (PID {pid}). Exiting.")
            sys.exit(1)
        except (OSError, ValueError):
            log.warning("Found stale lock file. Removing.")
            os.remove(lock_file)
    with open(lock_file, "w") as f:
        f.write(str(os.getpid()))

def release_lock():
    if os.path.exists("/tmp/import-blocklists.lock"):
        os.remove("/tmp/import-blocklists.lock")

# --- MAIN ---
def main():
    log.info("-" * 60)
    log.info("STARTING NEW BLOCKLIST IMPORT RUN")
    log.info("-" * 60)

    acquire_lock()
    try:
        dynamic_wl = fetch_dynamic_whitelist()
        combined_whitelist = list(set(CUSTOM_WHITELIST + dynamic_wl))
        log.info(f"Combined whitelist: {len(combined_whitelist)} entries "
                 f"({len(CUSTOM_WHITELIST)} static + {len(dynamic_wl)} dynamic)")

        log.info("Starting blocklist downloads...")
        v4_raw, v6_raw = get_blocklists()
        if not v4_raw and not v6_raw:
            log.error("No IPs downloaded. Check internet connection.")
            sys.exit(1)

        log.info("Optimizing...")
        v4_clean = optimize_and_filter(v4_raw, combined_whitelist)
        v6_clean = optimize_and_filter(v6_raw, combined_whitelist)

        total = len(v4_clean) + len(v6_clean)
        if total < MIN_IPS:
            log.error(f"Safety brake triggered: only {total} IPs (threshold: {MIN_IPS}). Keeping existing rules.")
            sys.exit(1)

        apply_nftables(v4_clean, v6_clean)

    finally:
        release_lock()

if __name__ == "__main__":
    main()
