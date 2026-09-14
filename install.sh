#!/bin/sh
# Installation script for import-blocklists

set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Please run as root (use sudo)" >&2
  exit 1
fi

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo "Options:"
  echo "  -w <ips>       Space-separated IPs or CIDRs to whitelist"
  echo "  -s <schedule>  Systemd timer schedule (e.g., '*-*-* 03,15:00:00')"
  echo "  -y             Non-interactive mode (accepts defaults if not provided)"
  echo "  -r             Run the importer immediately after installation"
  echo "  -h             Show this help message"
}

whitelist_input=""
schedule_input=""
interactive=1
run_now_input=0

while getopts "w:s:yrh" opt; do
  case "$opt" in
    w) whitelist_input="$OPTARG" ;;
    s) schedule_input="$OPTARG" ;;
    y) interactive=0 ;;
    r) run_now_input=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

echo "--- NFTables Blocklist Importer Installation ---"

if [ "$interactive" -eq 1 ]; then
  if [ -z "$whitelist_input" ]; then
    echo "Enter any additional IPs or CIDRs to whitelist (space-separated), or leave blank for none:"
    read -r user_ips
    whitelist_input="$user_ips"
  fi

  if [ -z "$schedule_input" ]; then
    echo ""
    echo "Select a systemd timer schedule:"
    echo "  1) Every day at 3 AM (default)"
    echo "  2) Twice a day (3 AM and 3 PM)"
    echo "  3) Custom schedule"
    printf "Enter choice [1-3] or press Enter for default: "
    read -r choice

    case "$choice" in
      2) schedule_input="*-*-* 03,15:00:00" ;;
      3)
        printf "Enter custom systemd timer schedule (e.g., '*-*-* 02,14:30:00'): "
        read -r custom_sched
        if [ -n "$custom_sched" ]; then
          schedule_input="$custom_sched"
        else
          schedule_input="*-*-* 03:00:00"
        fi
        ;;
      *) schedule_input="*-*-* 03:00:00" ;;
    esac
  fi

  if [ "$run_now_input" -eq 0 ]; then
    echo ""
    printf "Run the importer immediately after installation? (Y/n): "
    read -r run_choice
    case "$run_choice" in
      [nN]*) run_now_input=0 ;;
      *) run_now_input=1 ;;
    esac
  fi
fi

if [ -z "$schedule_input" ]; then
  schedule_input="*-*-* 03:00:00"
fi

echo "Configuring whitelist..."
mkdir -p /etc/import-blocklists
: > /etc/import-blocklists/whitelist.txt
if [ -n "$whitelist_input" ]; then
  set -f # disable globbing to prevent wildcard expansion
  for ip in $whitelist_input; do
    echo "$ip" >> /etc/import-blocklists/whitelist.txt
  done
  set +f
  echo "Whitelisted IPs saved to /etc/import-blocklists/whitelist.txt"
fi
chmod 644 /etc/import-blocklists/whitelist.txt

echo "Installing import-blocklists.py to /usr/local/bin/"
install -m 755 import-blocklists.py /usr/local/bin/import-blocklists.py

echo "Generating systemd service..."
cat <<EOF > /etc/systemd/system/import-blocklists.service
[Unit]
Description=NFTables Blocklist Importer
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/import-blocklists.py
StandardOutput=journal
StandardError=journal
EOF
chmod 644 /etc/systemd/system/import-blocklists.service

echo "Generating systemd timer with schedule: $schedule_input"
cat <<EOF > /etc/systemd/system/import-blocklists.timer
[Unit]
Description=Run NFTables Blocklist Importer scheduled

[Timer]
# Run on the specified schedule
OnCalendar=$schedule_input
# Randomize by up to 2 hours to prevent thundering herds on public APIs
RandomizedDelaySec=7200
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 644 /etc/systemd/system/import-blocklists.timer

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling and starting timer..."
systemctl enable --now import-blocklists.timer

if [ "$run_now_input" -eq 1 ]; then
  echo ""
  echo "Running import-blocklists for the first time..."
  systemctl start import-blocklists.service
fi

echo ""
echo "Installation complete!"
echo "Timer status     : systemctl status import-blocklists.timer"
echo "Trigger manually : systemctl start import-blocklists.service"
echo "View logs        : journalctl -fu import-blocklists.service"
echo "Check firewall   : sudo nft list chain inet import_blocklists prerouting_block"
