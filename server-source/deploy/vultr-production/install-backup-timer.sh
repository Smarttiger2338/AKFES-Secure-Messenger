#!/usr/bin/env bash
set -euo pipefail
cat > /etc/systemd/system/akfes-backup.service <<'EOF'
[Unit]
Description=AKFES encrypted data and PostgreSQL backup
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
User=root
ExecStart=/opt/akfes/app/deploy/vultr-production/backup.sh
EOF

cat > /etc/systemd/system/akfes-backup.timer <<'EOF'
[Unit]
Description=Run AKFES backup every day

[Timer]
OnCalendar=*-*-* 04:15:00 Asia/Seoul
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now akfes-backup.timer
systemctl list-timers akfes-backup.timer --no-pager
