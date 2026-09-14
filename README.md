# Blocklist Importer

A Python script that aggregates multiple IP blocklists, filters out whitelisted IP ranges (including dynamic Cloudflare and GitHub IP ranges), and loads the result into nftables.

## What it does

- Downloads IP ranges from multiple public blocklist sources.
- Builds separate IPv4 and IPv6 nftables sets.
- Excludes local/reserved ranges, user-defined whitelisted networks, and dynamically pulled Cloudflare and GitHub IP ranges.
- Collapses overlapping networks before applying the ruleset.
- Loads the rules into a dedicated nftables table and chain.
- Supports scheduled execution with systemd.

## Requirements

- Linux
- Python 3
- nftables
- Root privileges

## Installation

Clone the repository and run the installer:

```bash
git clone https://github.com/buildplan/blocklists.git
cd blocklists
sudo ./install.sh
```

The installer can be run interactively (it will prompt for optional IPs to whitelist and a custom systemd timer schedule) or non-interactively using CLI flags:

```bash
sudo ./install.sh -w "1.1.1.1 10.0.0.0/8" -s "*-*-* 03,15:00:00" -y
```

Available installer options:
- `-w <ips>` - Space-separated IPs or CIDRs to whitelist.
- `-s <schedule>` - Systemd timer schedule (default is `*-*-* 03:00:00`).
- `-y` - Non-interactive mode (accepts defaults if not provided).
- `-h` - Show help message.

The installer performs the following actions:
1. Writes user-defined whitelisted IPs to `/etc/import-blocklists/whitelist.txt`.
2. Copies `import-blocklists.py` to `/usr/local/bin`.
3. Generates the systemd timer configuration.
4. Enables and starts the systemd service and timer.

## Usage

Once installed, the systemd timer handles automated execution. 

To view the timer status:
```bash
systemctl status import-blocklists.timer
```

Run manually through systemd:

```bash
sudo systemctl start import-blocklists.service
```

Run the script directly:

```bash
sudo /usr/local/bin/import-blocklists.py
```

Check timer status:

```bash
systemctl status import-blocklists.timer
```

## Configuration

### Custom Whitelists

To manually add or remove custom IPs or CIDRs to the whitelist after installation, edit the file `/etc/import-blocklists/whitelist.txt`.

Example:
```text
10.0.0.0/8
192.168.1.50 # Internal monitoring server
```

The script will automatically parse this file during its next run and exclude these addresses from the blocklists.

## Arguments

The script supports these options:

- `--nft-table` - nftables table name to create or update. Default: `import_blocklists`
- `--log-file` - log file path. Default: `/var/log/import-blocklists.log`
- `--min-ips` - safety threshold to avoid applying a very small or broken list. Default: `200`
- `--workers` - number of download threads. Default: `10`
- `--timeout` - download timeout in seconds. Default: `15`
- `--retries` - download retries per source. Default: `3`

Example:

```bash
sudo /usr/local/bin/import-blocklists.py --workers 5 --timeout 30
```

## nftables layout

The script creates an `inet` table called `import_blocklists` with:

- A `v4_blocklist` set for blocked IPv4 networks.
- A `v6_blocklist` set for blocked IPv6 networks.
- A `prerouting_block` base chain attached to the `prerouting` hook at priority `-300`.

This places the blocklist early in the packet path, before the routing decision.

## Verification

### View packet counters

```bash
sudo nft list chain inet import_blocklists prerouting_block
```

Example output:

```bash
table inet import_blocklists {
    chain prerouting_block {
        type filter hook prerouting priority -300; policy accept;
        ip saddr @v4_blocklist counter packets 44300 bytes 2650786 drop
        ip6 saddr @v6_blocklist counter packets 0 bytes 0 drop
    }
}
```

If the `packets` and `bytes` counters increase over time, the kernel is matching and dropping traffic from addresses in the blocklist.

Note:

- `packets` is the number of matched packets.
- `bytes` is the total size of those matched packets.
- These counters do not represent unique source IPs.

### View counters with rule handles

```bash
sudo nft -a -n list chain inet import_blocklists prerouting_block
```

This is useful when you want numeric output and rule handles for troubleshooting or targeted counter resets.

### View the full nftables table

```bash
sudo nft -n list table inet import_blocklists
```

This shows the chain definition and the contents of the sets currently loaded into the kernel.

### Check whether a specific IP is blocked

IPv4:

```bash
sudo nft get element inet import_blocklists v4_blocklist '{ 1.2.3.4 }'
```

IPv6:

```bash
sudo nft get element inet import_blocklists v6_blocklist '{ 2001:db8::1 }'
```

If the element exists, nftables will return it. If not, it will report that the element was not found.

### Measure over a fixed time window

Reset the counters:

```bash
sudo nft reset rules inet import_blocklists prerouting_block
```

Then wait for a defined period, such as 1 hour or 24 hours, and check the chain again:

```bash
sudo nft list chain inet import_blocklists prerouting_block
```

This is the easiest way to measure how many packets the blocklist has dropped during that period.

## Troubleshooting

### The counters stay at zero

Possible reasons:

- No traffic from blocked IPs has reached the host yet.
- The import job has not run successfully.
- The sets are empty or smaller than expected.

Check the service and logs:

```bash
systemctl status import-blocklists.service
systemctl status import-blocklists.timer
sudo journalctl -u import-blocklists.service
sudo tail -f /var/log/import-blocklists.log
```

### A specific address should be blocked but is not

Check whether it exists in the relevant set:

```bash
sudo nft get element inet import_blocklists v4_blocklist '{ 1.2.3.4 }'
```

If it is missing, run the importer again and inspect the logs.

### `nft monitor trace` shows nothing

`nft monitor trace` only shows packets that have been marked for tracing with `meta nftrace set 1`. It does not automatically display every packet that matches the blocklist.

### IPv6 counters remain at zero

That usually means no blocked IPv6 traffic has matched yet, not necessarily that IPv6 filtering is broken.

## Continuous Integration

The repository includes CI checks for code quality, security scanning, and source availability monitoring.
