# =============================================================================
# Section 6 — Logging & Auditing   (CIS Ubuntu 24.04 v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section6_logging.yml.
# Most of Section 6.2 is Level 2.
# =============================================================================

# -----------------------------------------------------------------------------
# 6.1.x — journald / rsyslog
# -----------------------------------------------------------------------------
# 6.1.1.1.6 — journald Storage persistent.
c_6_1_1_1_6() {
    ensure_dir /etc/systemd/journald.conf.d 0755
    ensure_file_content /etc/systemd/journald.conf.d/60-cis.conf 0644 <<EOF
# Managed by CIS hardening — control 6.1.1.1.6
[Journal]
Storage=${CIS_6_1_JOURNALD_STORAGE}
EOF
    (( CHANGED )) && notify journald
    return 0
}
run 1 6.1.1.1.6 "journald Storage=${CIS_6_1_JOURNALD_STORAGE}" c_6_1_1_1_6

# 6.1.3.1 — restrictive permissions on all log files (enforced by systemd-tmpfiles
# on rotated/created logs).
c_6_1_3_1() {
    ensure_file_content /etc/tmpfiles.d/cis-logfiles.conf 0644 <<'EOF'
# Managed by CIS hardening — control 6.1.3.1
# systemd-tmpfiles enforces 0640 root:adm on rotated/created logs.
z /var/log/syslog 0640 root adm - -
Z /var/log 0640 root adm - -
EOF
}
run 1 6.1.3.1 "Log file permissions via tmpfiles.d (0640 root:adm)" c_6_1_3_1

# 6.1.2.8/6.1.2.9 — rsyslog TLS forwarding (L2). Off by default: needs a remote
# loghost + CA. Enabling without those breaks logging.
c_6_1_2_8() {
    if ! bool "$CIS_6_1_MANAGE_RSYSLOG_TLS"; then
        SKIP_REASON="opt-in, off by default (CIS_6_1_MANAGE_RSYSLOG_TLS=false) — needs remote loghost + CA"
        return 0
    fi
    pkg_present rsyslog-gnutls
}
run 2 6.1.2.8 "rsyslog-gnutls for TLS forwarding (opt-in)" c_6_1_2_8

# -----------------------------------------------------------------------------
# 6.2.x — auditd (Level 2)
# -----------------------------------------------------------------------------
c_6_2_gate() {
    # Shared gate for the 6.2 block.
    bool "$CIS_6_2_MANAGE_AUDITD"
}

# 6.2.1.1 — auditd + plugins installed.
c_6_2_1_1() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    pkg_present auditd audispd-plugins
}
run 2 6.2.1.1 "auditd + audispd-plugins installed" c_6_2_1_1

# 6.2.2.3 / 6.2.2.4 — actions when audit disk is full / low.
c_6_2_2() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if [[ ! -f /etc/audit/auditd.conf ]]; then
        SKIP_REASON="auditd not installed (no /etc/audit/auditd.conf)"
        return 0
    fi
    ensure_line /etc/audit/auditd.conf '^disk_full_action[[:space:]]*=' \
        "disk_full_action = ${CIS_6_2_DISK_FULL_ACTION}"
    ensure_line /etc/audit/auditd.conf '^space_left_action[[:space:]]*=' \
        "space_left_action = ${CIS_6_2_SPACE_LEFT_ACTION}"
    ensure_line /etc/audit/auditd.conf '^admin_space_left_action[[:space:]]*=' \
        "admin_space_left_action = ${CIS_6_2_DISK_FULL_ACTION}"
}
run 2 6.2.2.3 "auditd disk-full handling" c_6_2_2

# 6.2.3.x — audit rules. One managed file; augenrules loads it.
c_6_2_3() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if [[ ! -d /etc/audit/rules.d ]]; then
        SKIP_REASON="auditd not installed (no /etc/audit/rules.d)"
        return 0
    fi
    ensure_file_content /etc/audit/rules.d/60-cis.rules 0640 <<'EOF'
## Managed by CIS hardening — Section 6.2.3
## 6.2.3.2 — actions as another user
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
## 6.2.3.7 — /etc/hosts, /etc/hostname
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
## 6.2.3.8 — /etc/network, /etc/networks
-w /etc/network/ -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
## 6.2.3.9 — /etc/netplan
-w /etc/netplan/ -p wa -k system-locale
## 6.2.3.10 — privileged commands (generated list trimmed to common ones)
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged
## 6.2.3.14 — /etc/security/opasswd
-w /etc/security/opasswd -p wa -k usergroup_modification
## 6.2.3.15 — /etc/nsswitch.conf
-w /etc/nsswitch.conf -p wa -k usergroup_modification
## 6.2.3.16 — /etc/pam.conf, /etc/pam.d
-w /etc/pam.conf -p wa -k usergroup_modification
-w /etc/pam.d/ -p wa -k usergroup_modification
## 6.2.3.17 — unsuccessful file access attempts
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
## 6.2.3.18 — DAC permission modification events
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
## 6.2.3.22 — file deletion events by users
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
## 6.2.3.28 — kernel module load/unload/modify
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules
-w /usr/bin/kmod -p x -k kernel_modules
EOF
    (( CHANGED )) && notify auditd
    return 0
}
run 2 6.2.3 "CIS audit rules (60-cis.rules)" c_6_2_3

# 6.2.3.29 — make the audit configuration immutable (-e 2). [REBOOT-REQUIRED]
# to clear. Off by default so rule changes don't require a reboot mid-build.
c_6_2_3_29() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if ! bool "$CIS_6_2_AUDIT_IMMUTABLE"; then
        SKIP_REASON="opt-in, off by default (CIS_6_2_AUDIT_IMMUTABLE=false) [REBOOT-REQUIRED to undo]"
        return 0
    fi
    if [[ ! -d /etc/audit/rules.d ]]; then
        SKIP_REASON="auditd not installed"
        return 0
    fi
    ensure_file_content /etc/audit/rules.d/99-finalize.rules 0640 <<'EOF'
# Managed by CIS hardening — control 6.2.3.29
-e 2
EOF
    (( CHANGED )) && notify auditd
    return 0
}
run 2 6.2.3.29 "Audit config immutable -e 2 (opt-in)" c_6_2_3_29
