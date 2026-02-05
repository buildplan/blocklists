#!/usr/bin/env python3
"""
Fail2Ban/NFTables Blocklist Importer (Pure Python Version)
Features: Parallel downloads, In-memory processing, Native NFTables integration.
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
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ROOT CHECK ---
if os.geteuid() != 0:
    print("Error: This script must be run as root (use sudo).", file=sys.stderr)
    sys.exit(1)

# --- CONFIGURATION ---
NFT_TABLE = "import_blocklists"
LOG_FILE = "/var/log/import-blocklists.log"
LOG_MAX_LINES = 2000
MIN_IPS = 200  # Safety brake threshold
MAX_WORKERS = 10  # How many downloads to run at once
TIMEOUT = 15  # Seconds per request
RETRIES = 3

# Custom Whitelist (IPs or CIDRs)
CUSTOM_WHITELIST = [
    "1.1.1.1",          # Cloudflare DNS
    "8.8.8.8",          # Google DNS
    "::1",              # Localhost
    "2001:4860:4860::8888",
    "2606:4700:4700::1111"
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
]

# --- SETUP LOGGING ---
def truncate_log_if_needed():
    """Truncate log file if it exceeds MAX_LINES, keeping most recent entries."""
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        if len(lines) > LOG_MAX_LINES:
            with open(LOG_FILE, 'w') as f:
                f.write(f"[Log truncated - kept last {LOG_MAX_LINES} lines]\n")
                f.writelines(lines[-LOG_MAX_LINES:])
    except Exception as e:
        print(f"Warning: Could not truncate log: {e}", file=sys.stderr)

truncate_log_if_needed()
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger()

def fetch_url(name, url):
    """Downloads a URL with retries and returns the text content."""
    attempt = 0
    while attempt < RETRIES:
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Blocklist-Updater/2.0 (Python)'}
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                if response.status == 200:
                    return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            attempt += 1
            if attempt == RETRIES:
                log.warning(f"{name}: Failed after {RETRIES} retries. Error: {e}")
                return None
            time.sleep(1)
    return None

def is_safe_ip(net):
    """Returns True if the IP is global and safe to block (not private/local)."""
    # Universal checks (v4 and v6)
    if net.is_private: return False
    if net.is_loopback: return False
    if net.is_link_local: return False
    if net.is_multicast: return False
    if net.is_reserved: return False

    # IPv4 specific checks
    if isinstance(net, ipaddress.IPv4Network):
        if str(net).startswith('0.'): return False

    return True

def parse_ips(name, text):
    """Extracts valid IP networks from text, handling URLs, comments, and DShield format."""
    valid_nets = []

    # Regex to find IPv4 addresses inside URLs
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    for line in text.splitlines():
        line = line.strip()
        if '#' in line: line = line.split('#', 1)[0]
        if ';' in line: line = line.split(';', 1)[0]
        line = line.strip()
        if not line: continue

        net = None

        # DShield handling
        if name == "DShield":
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                try:
                    prefix = int(parts[2])
                    if 0 <= prefix <= 32:
                        net = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                except ValueError:
                    pass

        # 2. Standard Parsing
        if net is None:
            try:
                token = line.split()[0]
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                match = ipv4_pattern.search(line)
                if match:
                    try:
                        net = ipaddress.ip_network(match.group(), strict=False)
                    except ValueError:
                        pass

        # 3. Security Filter
        if net and is_safe_ip(net):
            valid_nets.append(net)

    return valid_nets

def get_blocklists():
    """Downloads all blocklists in parallel."""
    v4_list = []
    v6_list = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_name = {executor.submit(fetch_url, name, url): name for name, url in BLOCKLISTS}

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            content = future.result()

            if content:
                nets = parse_ips(name, content)
                if not nets:
                    log.warning(f"{name}: Downloaded empty or invalid list.")
                    continue

                count = len(nets)
                log.info(f"{name}: Downloaded {count} entries.")

                for net in nets:
                    if isinstance(net, ipaddress.IPv4Network):
                        v4_list.append(net)
                    else:
                        v6_list.append(net)

    return v4_list, v6_list

def optimize_and_filter(networks, whitelist):
    """Removes whitelisted IPs and merges overlapping subnets."""
    # 1. Collapse overlaps
    networks = list(ipaddress.collapse_addresses(networks))

    # 2. Process Whitelist
    whitelist_nets = [ipaddress.ip_network(w, strict=False) for w in whitelist]
    final_list = []

    for net in networks:
        candidates = [net]

        for wl in whitelist_nets:
            if net.version != wl.version:
                continue

            new_candidates = []
            for candidate in candidates:
                if not candidate.overlaps(wl):
                    new_candidates.append(candidate)
                    continue

                if wl.supernet_of(candidate) or wl == candidate:
                    continue

                try:
                    subnets = list(candidate.address_exclude(wl))
                    new_candidates.extend(subnets)
                except ValueError as e:
                    log.debug(f"Could not exclude {wl} from {candidate}: {e}")
                    new_candidates.append(candidate)
                except ValueError:
                    pass

            candidates = new_candidates
            if not candidates:
                break

        final_list.extend(candidates)

    return list(ipaddress.collapse_addresses(final_list))

def apply_nftables(v4_nets, v6_nets):
    """Generates NFTables config and applies it using a secure tempfile."""
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

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        tmp.write(config)
        nft_path = tmp.name

    try:
        # Validation Run
        chk = subprocess.run(["nft", "-c", "-f", nft_path], capture_output=True, text=True)
        if chk.returncode != 0:
            log.error("NFTables syntax check failed!")
            log.error(chk.stderr)
            return False

        # Apply
        # 1. Flush old table (ignore error if doesn't exist)
        subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], stderr=subprocess.DEVNULL)

        # 2. Load new rules
        apply = subprocess.run(["nft", "-f", nft_path], capture_output=True, text=True)

        if apply.returncode == 0:
            log.info(f"✓ Success! Blocked {len(v4_nets)} IPv4 and {len(v6_nets)} IPv6 networks.")
            return True
        else:
            log.error("Failed to apply NFTables rules.")
            log.error(apply.stderr)
            return False

    finally:
        # clean up the temp file
        if os.path.exists(nft_path):
            os.remove(nft_path)

def main():
    # File locking
    lock_file = "/tmp/import-blocklists.lock"
    if os.path.exists(lock_file):
        try:
            with open(lock_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            log.error(f"Script already running (PID {pid}). Exiting.")
            sys.exit(1)
        except (OSError, ValueError):
            log.warning("Stale lock file found. Removing.")
            os.remove(lock_file)

    with open(lock_file, 'w') as f:
        f.write(str(os.getpid()))

    try:
        log.info("Starting parallel download of blocklists...")

        # 1. Download
        v4_raw, v6_raw = get_blocklists()

        if not v4_raw and not v6_raw:
            log.error("No IPs downloaded. Check internet connection.")
            sys.exit(1)

        # 2. Optimize
        log.info("Optimizing lists (Merging and Whitelisting)...")
        v4_clean = optimize_and_filter(v4_raw, CUSTOM_WHITELIST)
        v6_clean = optimize_and_filter(v6_raw, CUSTOM_WHITELIST)

        # 3. Safety Check
        total_ips = len(v4_clean) + len(v6_clean)
        if total_ips < MIN_IPS:
            log.error(f"Safety Brake: Only found {total_ips} IPs (Threshold: {MIN_IPS}). Keeping old rules.")
            sys.exit(1)

        # 4. Apply
        apply_nftables(v4_clean, v6_clean)

    finally:
        if os.path.exists(lock_file):
            os.remove(lock_file)

if __name__ == "__main__":
    main()
