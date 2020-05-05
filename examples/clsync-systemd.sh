#!/bin/sh

# Take the service file from this directory if it is not installed
# on your system.
# cp 'clsync@.service' /etc/systemd/system/
systemctl enable clsync@SomeConfig
mkdir -p /etc/clsync
cat > /etc/clsync/clsync.conf <<EOF
[SomeConfig]
mode = simple
watch-dir = /tmp
sync-handler = echo
EOF
systemctl start clsync@SomeConfig
systemctl status clsync@SomeConfig

