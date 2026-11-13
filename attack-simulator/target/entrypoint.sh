#!/bin/bash
set -euo pipefail

mkdir -p /var/run/sshd /var/log/ssh-lab
: > /var/log/ssh-lab/secure
chmod 0644 /var/log/ssh-lab/secure
ssh-keygen -A
/usr/sbin/sshd -t
/usr/sbin/rsyslogd
exec /usr/sbin/sshd -D
