#!/usr/bin/env python3
"""
2026-06-26
NFTables Blocklist Importer
Fetches reputable threat intelligence blocklists and applies them as an
nftables drop table. GitHub + Cloudflare + all RFC private/local ranges
are whitelisted.
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
import argparse
import fcntl
import shutil
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ROOT CHECK ---
if os.geteuid() != 0:
    print("Error: This script must be run as root (use sudo).", file=sys.stderr)
    sys.exit(1)

if not shutil.which("nft"):
    print("Error: 'nft' command not found. Please install nftables.", file=sys.stderr)
    sys.exit(1)

# --- CONFIGURATION DEFAULTS ---
NFT_TABLE       = "import_blocklists"
LOG_FILE        = "/var/log/import-blocklists.log"
PERSIST_FILE    = "/etc/import-blocklists/ruleset.nft"
SYSTEMD_SERVICE = "/etc/systemd/system/import-blocklists-restore.service"
MIN_IPS         = 200
MAX_WORKERS     = 5       # Kept low to avoid rate-limiting on Spamhaus/abuse.ch
TIMEOUT         = 15
RETRIES         = 3

# --- LOGGING ---
log = logging.getLogger()

def setup_logging(log_file):
    log.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    log.addHandler(sh)

    if log_file:
        try:
            fh = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=2)
            fh.setFormatter(formatter)
            log.addHandler(fh)
        except Exception as e:
            print(f"Warning: Could not setup file logging to {log_file}: {e}", file=sys.stderr)

# --- LOCAL / RFC PRIVATE CIDR WHITELIST ---
LOCAL_CIDR_WHITELIST = [
    # Loopback
    "127.0.0.0/8", "::1/128",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "fe80::/10", "fc00::/7", "100.64.0.0/10",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
    "224.0.0.0/4", "240.0.0.0/4", "ff00::/8",
]

# --- STATIC WHITELISTS (specific trusted hosts + CDN fallbacks) ---
CUSTOM_WHITELIST = [
    "1.1.1.1", "8.8.8.8", "9.9.9.9",
    "2001:4860:4860::8888", "2606:4700:4700::1111",
] + LOCAL_CIDR_WHITELIST

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
    ("Spamhaus DROPv6",    "https://www.spamhaus.org/drop/dropv6.txt"),
    ("Emerging Threats",   "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("Feodo Tracker",      "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("URLhaus",            "https://urlhaus.abuse.ch/downloads/text_online/"),
    ("CI Army",            "https://cinsscore.com/list/ci-badguys.txt"),
    ("Clean Talk",         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cleantalk_1d.ipset"),
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
    ("list.rtbh.com.tr",   "https://list.rtbh.com.tr/output.txt"),
    ("DataShield-BL",      "https://gitlab.com/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt"),
    # ("Bitwire",          "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt"),
]

# --- DYNAMIC WHITELIST ---

def fetch_user_whitelist():
    """Load user-defined whitelist from /etc/import-blocklists/whitelist.txt."""
    user_wl = []
    wl_path = "/etc/import-blocklists/whitelist.txt"
    if os.path.exists(wl_path):
        try:
            with open(wl_path, "r") as f:
                for line in f:
                    ip = line.split('#')[0].strip()
                    if ip:
                        user_wl.append(ip)
        except Exception as e:
            log.warning(f"Failed to read user whitelist: {e}")
    return user_wl

def fetch_dynamic_whitelist():
    """Fetch live IP ranges from GitHub and Cloudflare APIs, fall back to static lists."""
    ranges = []

    # GitHub
    try:
        req = urllib.request.Request(
            "https://api.github.com/meta",
            headers={"User-Agent": "Blocklist-Updater/3.2", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        seen = set()
        for key in ("hooks", "web", "git", "api"):
            for cidr in data.get(key, []):
                if cidr not in seen:
                    ranges.append(cidr)
                    seen.add(cidr)
        log.info(f"Whitelist: fetched {len(seen)} GitHub ranges from API")
        if len(seen) > 200:
            log.warning(f"GitHub whitelist unusually large ({len(seen)} ranges) — verify API response")
    except Exception as e:
        log.warning(f"Whitelist: GitHub API failed ({e}), using static fallback ({len(GITHUB_STATIC)} ranges)")
        ranges.extend(GITHUB_STATIC)

    # Cloudflare
    try:
        req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/ips",
            headers={"User-Agent": "Blocklist-Updater/3.2", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        cf_ranges = (
            data.get("result", {}).get("ipv4_cidrs", []) +
            data.get("result", {}).get("ipv6_cidrs", [])
        )
        if cf_ranges:
            ranges.extend(cf_ranges)
            log.info(f"Whitelist: fetched {len(cf_ranges)} Cloudflare ranges from API")
        else:
            raise ValueError("Empty result from Cloudflare API")
    except Exception as e:
        log.warning(f"Whitelist: Cloudflare API failed ({e}), using static fallback ({len(CLOUDFLARE_STATIC)} ranges)")
        ranges.extend(CLOUDFLARE_STATIC)

    return ranges

# --- BLOCKLIST DOWNLOAD + PARSE ---

def fetch_url(name, url):
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Blocklist-Updater/3.2"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                if response.status == 200:
                    return response.read().decode("utf-8", errors="ignore")
        except Exception as e:
            if attempt == RETRIES - 1:
                log.warning(f"  x {name}: Failed after {RETRIES} retries -- {e}")
            else:
                time.sleep(1)
    return None

def is_safe_ip(net):
    """Reject IPs that should never appear in a blocklist."""
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
    """Download all sources concurrently. Returns raw IP lists and per-source stats."""
    v4_list, v6_list = [], []
    source_stats = {}  # name -> int count | "failed" | "empty"

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_name = {executor.submit(fetch_url, name, url): name for name, url in BLOCKLISTS}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            content = future.result()
            if content is None:
                source_stats[name] = "failed"
                continue
            nets = parse_ips(name, content)
            if not nets:
                log.warning(f"  x {name}: Downloaded but contained no valid IPs")
                source_stats[name] = "empty"
                continue
            source_stats[name] = len(nets)
            log.info(f"  ✓ {name}: {len(nets):,} IPs")
            for net in nets:
                (v4_list if net.version == 4 else v6_list).append(net)

    return v4_list, v6_list, source_stats

# --- OPTIMISE + FILTER ---

def optimize_and_filter(networks, whitelist):
    """Collapse overlapping subnets and carve out whitelisted ranges."""
    if not networks:
        return []
    networks = list(ipaddress.collapse_addresses(networks))

    # Build version-matched whitelist to avoid cross-version comparisons
    wl_parsed = []
    for w in whitelist:
        try:
            wn = ipaddress.ip_network(w, strict=False)
            if wn.version == networks[0].version:
                wl_parsed.append(wn)
        except ValueError:
            pass

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

# --- NFTABLES APPLY ---

def build_ruleset(v4_nets, v6_nets):
    """Build the nftables ruleset string."""
    v4_str = ", ".join(str(n) for n in v4_nets)
    v6_str = ", ".join(str(n) for n in v6_nets)

    return f"""# Generated by import-blocklists -- {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
# Hook: prerouting priority -300
#   Before conntrack (-200)   Stateless drop for maximum efficiency
#   Before Docker DNAT (-100) Drops fire before container port rewrites
#
# Atomic reload: delete table + fresh table block in one nft -f transaction.
table inet {NFT_TABLE} {{}}
delete table inet {NFT_TABLE}

table inet {NFT_TABLE} {{
    set v4_blocklist {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {v4_str} }}
    }}

    set v6_blocklist {{
        type ipv6_addr
        flags interval
        auto-merge
        elements = {{ {v6_str} }}
    }}

    chain prerouting_block {{
        type filter hook prerouting priority -300; policy accept;
        ip  saddr @v4_blocklist counter drop
        ip6 saddr @v6_blocklist counter drop
    }}
}}
"""

def apply_nftables(v4_nets, v6_nets, dry_run=False):
    """Generate, syntax-check, and atomically apply the nftables ruleset."""
    ruleset = build_ruleset(v4_nets, v6_nets)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as tmp:
        tmp.write(ruleset)
        nft_path = tmp.name

    try:
        # Syntax check first -- never apply a broken ruleset
        chk = subprocess.run(["nft", "-c", "-f", nft_path], capture_output=True, text=True)
        if chk.returncode != 0:
            log.error(f"nftables syntax check failed:\n{chk.stderr.strip()}")
            return False

        if dry_run:
            log.info(f"[DRY RUN] Syntax check passed -- ruleset at {nft_path} (not applied, not deleted)")
            return True  # Skip cleanup so user can inspect the file

        # Atomic apply
        result = subprocess.run(["nft", "-f", nft_path], capture_output=True, text=True)
        if result.returncode != 0:
            log.error(f"Failed to apply nftables rules:\n{result.stderr.strip()}")
            return False

        log.info(f"nftables applied: {len(v4_nets):,} IPv4 and {len(v6_nets):,} IPv6 networks blocked")

        # Persist for reboot survival
        persist_ruleset(ruleset)
        return True

    finally:
        if os.path.exists(nft_path) and not dry_run:
            os.remove(nft_path)

# --- PERSISTENCE -- dedicated systemd oneshot, no /etc/nftables.conf dependency ---

def persist_ruleset(ruleset):
    try:
        os.makedirs("/etc/import-blocklists", exist_ok=True)
        with open(PERSIST_FILE, "w") as f:
            f.write(ruleset)
        os.chmod(PERSIST_FILE, 0o640)
    except Exception as e:
        log.warning(f"Could not save ruleset to {PERSIST_FILE}: {e}")
        return

    service_unit = f"""[Unit]
Description=Restore import-blocklists nftables blocklist ruleset
After=network.target
Before=docker.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f {PERSIST_FILE}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    try:
        first_install = not os.path.exists(SYSTEMD_SERVICE)

        with open(SYSTEMD_SERVICE, "w") as f:
            f.write(service_unit)
        os.chmod(SYSTEMD_SERVICE, 0o644)

        if first_install:
            subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
            enable = subprocess.run(
                ["systemctl", "enable", "import-blocklists-restore.service"],
                capture_output=True, text=True
            )
            if enable.returncode == 0:
                log.info("Restore service installed and enabled (runs at boot, before Docker)")
            else:
                log.warning(f"Could not enable restore service: {enable.stderr.strip()}")
        else:
            log.info(f"Ruleset updated at {PERSIST_FILE} (restore service already enabled)")

    except Exception as e:
        log.warning(f"Could not install systemd restore service: {e}")

# --- LOCKING ---

LOCK_FD   = None
LOCK_FILE = "/run/import-blocklists.lock"

def acquire_lock():
    global LOCK_FD
    try:
        LOCK_FD = open(LOCK_FILE, "w")
        fcntl.flock(LOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)
        LOCK_FD.write(str(os.getpid()))
        LOCK_FD.flush()
    except (BlockingIOError, OSError):
        log.error("Script is already running. Could not acquire lock. Exiting.")
        sys.exit(1)

def release_lock():
    if LOCK_FD:
        try:
            fcntl.flock(LOCK_FD, fcntl.LOCK_UN)
            LOCK_FD.close()
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
        except Exception as e:
            log.error(f"Error releasing lock: {e}")

# --- SUMMARY ---

def print_summary(source_stats, v4_raw, v6_raw, v4_clean, v6_clean,
                  whitelist_counts, applied, elapsed, dry_run):
    total_sources = len(BLOCKLISTS)
    succeeded     = sum(1 for v in source_stats.values() if isinstance(v, int))
    failed        = sum(1 for v in source_stats.values() if v == "failed")
    empty         = sum(1 for v in source_stats.values() if v == "empty")
    raw_total     = len(v4_raw) + len(v6_raw)
    clean_total   = len(v4_clean) + len(v6_clean)
    reduction     = raw_total - clean_total
    reduction_pct = (reduction / raw_total * 100) if raw_total else 0

    sep = "=" * 62
    log.info(sep)
    log.info("  BLOCKLIST IMPORT SUMMARY")
    log.info(sep)

    log.info(f"  Sources       : {succeeded}/{total_sources} succeeded  "
             f"({failed} failed, {empty} empty)")

    top = sorted(
        [(k, v) for k, v in source_stats.items() if isinstance(v, int)],
        key=lambda x: x[1], reverse=True
    )[:5]
    if top:
        log.info("  Top feeds     : " + ", ".join(f"{n} ({c:,})" for n, c in top))

    failed_names = [k for k, v in source_stats.items() if v == "failed"]
    if failed_names:
        log.info("  Failed feeds  : " + ", ".join(failed_names))

    log.info(f"  Raw IPs       : {raw_total:>10,}  "
             f"(IPv4: {len(v4_raw):,}  IPv6: {len(v6_raw):,})")
    log.info(f"  After collapse: {clean_total:>10,}  "
             f"(IPv4: {len(v4_clean):,}  IPv6: {len(v6_clean):,})")
    log.info(f"  Reduction     : {reduction:>10,}  "
             f"({reduction_pct:.1f}% collapsed/whitelisted)")
    log.info(f"  Whitelist     : {whitelist_counts['total']:,} entries  "
             f"(static hosts: {whitelist_counts['static']}  "
             f"local CIDRs: {whitelist_counts['local']}  "
             f"dynamic: {whitelist_counts['dynamic']}  "
             f"user: {whitelist_counts['user']})")
    log.info(f"  Hook          : prerouting priority -300  "
             f"(pre-conntrack, pre-Docker DNAT)")

    if dry_run:
        status = "[DRY RUN -- not applied]"
    else:
        status = "APPLIED + persisted" if applied else "FAILED to apply"
    log.info(f"  nftables      : {status}")
    log.info(f"  Duration      : {elapsed:.1f}s")
    log.info(sep)

# --- MAIN ---

def main():
    global NFT_TABLE, LOG_FILE, MIN_IPS, MAX_WORKERS, TIMEOUT, RETRIES

    parser = argparse.ArgumentParser(
        description="NFTables Blocklist Importer -- blocks threat IPs at prerouting, covering both host and Docker container traffic"
    )
    parser.add_argument("--nft-table",  default=NFT_TABLE,     help="nftables table name")
    parser.add_argument("--log-file",   default=LOG_FILE,      help="Log file path")
    parser.add_argument("--min-ips",    type=int, default=MIN_IPS,     help="Minimum IP safety threshold")
    parser.add_argument("--workers",    type=int, default=MAX_WORKERS, help="Number of download threads")
    parser.add_argument("--timeout",    type=int, default=TIMEOUT,     help="Download timeout in seconds")
    parser.add_argument("--retries",    type=int, default=RETRIES,     help="Download retries per source")
    parser.add_argument("--dry-run",    action="store_true",           help="Validate and build ruleset without applying")
    args = parser.parse_args()

    NFT_TABLE   = args.nft_table
    LOG_FILE    = args.log_file
    MIN_IPS     = args.min_ips
    MAX_WORKERS = args.workers
    TIMEOUT     = args.timeout
    RETRIES     = args.retries
    dry_run     = args.dry_run

    setup_logging(LOG_FILE)
    start_time = time.monotonic()

    log.info("=" * 62)
    log.info("  STARTING BLOCKLIST IMPORT RUN" + (" [DRY RUN]" if dry_run else ""))
    log.info("=" * 62)

    acquire_lock()
    try:
        # Whitelist assembly
        dynamic_wl = fetch_dynamic_whitelist()
        user_wl    = fetch_user_whitelist()
        combined_whitelist = list(set(CUSTOM_WHITELIST + dynamic_wl + user_wl))

        whitelist_counts = {
            "static":  len(CUSTOM_WHITELIST) - len(LOCAL_CIDR_WHITELIST),
            "local":   len(LOCAL_CIDR_WHITELIST),
            "dynamic": len(dynamic_wl),
            "user":    len(user_wl),
            "total":   len(combined_whitelist),
        }
        log.info(f"Whitelist: {whitelist_counts['total']} entries  "
                 f"(static hosts: {whitelist_counts['static']}  "
                 f"local CIDRs: {whitelist_counts['local']}  "
                 f"dynamic: {whitelist_counts['dynamic']}  "
                 f"user: {whitelist_counts['user']})")

        # Download
        log.info(f"Downloading {len(BLOCKLISTS)} blocklist sources "
                 f"(workers: {MAX_WORKERS}, timeout: {TIMEOUT}s)...")
        v4_raw, v6_raw, source_stats = get_blocklists()

        if not v4_raw and not v6_raw:
            log.error("No IPs downloaded from any source. Check internet connectivity.")
            sys.exit(1)

        # Optimise
        log.info("Collapsing and filtering...")
        v4_clean = optimize_and_filter(v4_raw, combined_whitelist)
        v6_clean = optimize_and_filter(v6_raw, combined_whitelist)

        total = len(v4_clean) + len(v6_clean)
        if total < MIN_IPS:
            log.error(f"Safety brake: only {total:,} networks after filtering "
                      f"(threshold: {MIN_IPS:,}). Existing rules preserved.")
            sys.exit(1)

        # Apply
        applied = apply_nftables(v4_clean, v6_clean, dry_run=dry_run)

        # Summary
        elapsed = time.monotonic() - start_time
        print_summary(source_stats, v4_raw, v6_raw, v4_clean, v6_clean,
                      whitelist_counts, applied, elapsed, dry_run)

    finally:
        release_lock()

if __name__ == "__main__":
    main()
