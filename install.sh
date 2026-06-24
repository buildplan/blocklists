#!/usr/bin/env bash
# Installation script for import-blocklists

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "Installing import-blocklists.py to /usr/local/bin/"
install -m 755 import-blocklists.py /usr/local/bin/import-blocklists.py

echo "Installing systemd units..."
install -m 644 systemd/import-blocklists.service /etc/systemd/system/
install -m 644 systemd/import-blocklists.timer /etc/systemd/system/

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling and starting timer..."
systemctl enable --now import-blocklists.timer

echo "Installation complete!"
echo "You can check the timer status with: systemctl status import-blocklists.timer"
echo "You can trigger a run manually with: systemctl start import-blocklists.service"
