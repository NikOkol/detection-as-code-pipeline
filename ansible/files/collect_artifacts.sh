#!/usr/bin/env bash
set -euo pipefail

# Скрипт собирает syslog, journal, audit и osquery-логи в /vagrant/artifacts
TS=$(date -u +"%Y%m%dT%H%M%SZ")
ART_DIR="/vagrant/artifacts/atomic_artifacts_${TS}"
mkdir -p "${ART_DIR}"
echo "Collecting artifacts to ${ART_DIR}" >&2

# Copy syslog (Debian/Ubuntu)
if [ -f /var/log/syslog ]; then
  cp /var/log/syslog "${ART_DIR}/syslog" || true
fi

# Save journal
journalctl --no-pager > "${ART_DIR}/journalctl.log" || true

# Audit logs
if [ -f /var/log/audit/audit.log ]; then
  mkdir -p "${ART_DIR}/audit"
  cp /var/log/audit/audit.log "${ART_DIR}/audit/" || true
fi

# osquery logs (if present)
if [ -d /var/log/osquery ]; then
  cp -r /var/log/osquery "${ART_DIR}/osquery" || true
fi

# Save any atomic-specific logs
if [ -f /var/log/atomic/last_run.log ]; then
  cp /var/log/atomic/last_run.log "${ART_DIR}/last_run.log" || true
fi

# Create compressed archive for easy download on host
pushd /vagrant/artifacts >/dev/null 2>&1 || true
tar -czf "atomic_artifacts_${TS}.tar.gz" "atomic_artifacts_${TS}"
popd >/dev/null 2>&1 || true

echo "Artifacts saved to /vagrant/artifacts/atomic_artifacts_${TS}.tar.gz" >&2
chmod -R a+r /vagrant/artifacts || true