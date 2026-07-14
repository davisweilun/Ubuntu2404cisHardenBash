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

# 6.1.3.1 — restrictive permissions on all log files, applied live.
# NOTE: an earlier revision shipped a recursive tmpfiles rule
# ("Z /var/log 0640 root adm") that also stripped execute bits from
# DIRECTORIES under /var/log at boot, breaking log writers. This control
# replaces that rule and repairs any such damage.
c_6_1_3_1() {
    ensure_file_content /etc/tmpfiles.d/cis-logfiles.conf 0644 <<'EOF'
# Managed by CIS hardening — control 6.1.3.1
z /var/log/syslog 0640 root adm - -
EOF
    # Directory sanity (repair + Ubuntu defaults): dirs must stay traversable.
    [[ -d /var/log ]] || return 0
    if getent group syslog >/dev/null; then
        ensure_perms /var/log 0775 root syslog
    else
        ensure_perms /var/log 0755 root root
    fi
    local d bn
    while IFS= read -r d; do
        bn=$(basename "$d")
        case $bn in
            journal) ensure_perms "$d" 2755 root systemd-journal ;;
            private) ensure_perms "$d" 0700 root root ;;
            *)  # repair non-traversable dirs left by the old recursive rule
                local dm
                dm=$(stat -c '%a' "$d")
                if (( (8#$dm & 8#0111) == 0 )); then
                    CHANGED=1
                    (( DRY_RUN )) || chmod 0755 "$d"
                fi ;;
        esac
    done < <(find /var/log -mindepth 1 -type d)
    # File classes per the benchmark's own remediation script.
    local f n=0
    while IFS= read -r f; do
        bn=$(basename "$f")
        case $bn in
            lastlog|lastlog.*|wtmp|wtmp.*|wtmp-*|btmp|btmp.*|btmp-*)
                # 0664 or more restrictive, group utmp (or root)
                local cm cg
                read -r cm cg <<<"$(stat -c '%a %G' "$f")"
                if (( 8#$cm & 8#0113 )) || [[ $cg != utmp && $cg != root ]]; then
                    CHANGED=1; n=$((n + 1))
                    if (( ! DRY_RUN )); then
                        chmod u-x,g-x,o-wx "$f"
                        chgrp utmp "$f" 2>/dev/null || true
                    fi
                fi ;;
            *.journal|*.journal~)
                # journald manages perms, but the old recursive tmpfiles rule
                # chgrp'ed existing journals to adm; the benchmark requires
                # group root or systemd-journal. Repair without touching mode.
                local jg
                jg=$(stat -c '%G' "$f")
                if [[ $jg != root && $jg != systemd-journal ]]; then
                    CHANGED=1; n=$((n + 1))
                    if (( ! DRY_RUN )); then
                        chgrp systemd-journal "$f" 2>>"$LOG_FILE" \
                            || chgrp root "$f" 2>>"$LOG_FILE" || true
                    fi
                fi ;;
            *)
                # 0640 or more restrictive: clear u+x, g+wx, o+rwx if set
                if [[ -n $(find "$f" -perm /0137 2>/dev/null) ]]; then
                    CHANGED=1; n=$((n + 1))
                    (( DRY_RUN )) || chmod u-x,g-wx,o-rwx "$f"
                fi ;;
        esac
    done < <(find /var/log -type f)
    (( n )) && EXTRA_MSG="$n log file(s) tightened"
    return 0
}
# NOTE: the run call for 6.1.3.1 is at the END of this file so the sweep also
# covers log files created by later controls in the same run (e.g. AIDE).

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

# 6.2.1.3 / 6.2.1.4 — audit processes that start before auditd: kernel cmdline
# audit=1 + audit_backlog_limit. [REBOOT-REQUIRED] for runtime effect; the
# scanner checks grub.cfg, which update-grub refreshes immediately.
c_6_2_1_grub() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if ! bool "$CIS_6_2_GRUB_AUDIT"; then
        SKIP_REASON="disabled via CIS_6_2_GRUB_AUDIT"
        return 0
    fi
    if [[ ! -f /etc/default/grub ]] || ! command -v update-grub >/dev/null; then
        SKIP_REASON="GRUB not present on this host"
        return 0
    fi
    local cur val tok out=()
    cur=$(grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub | head -1)
    val=${cur#*=}; val=${val#\"}; val=${val%\"}
    # drop any existing audit tokens, then append the desired ones
    for tok in $val; do
        case $tok in
            audit=*|audit_backlog_limit=*) ;;
            *) out+=("$tok") ;;
        esac
    done
    out+=("audit=1" "audit_backlog_limit=${CIS_6_2_BACKLOG_LIMIT}")
    local newval="${out[*]}"
    [[ $newval == "$val" ]] && return 0
    ensure_line /etc/default/grub '^GRUB_CMDLINE_LINUX=' "GRUB_CMDLINE_LINUX=\"$newval\""
    (( CHANGED )) && notify grub
    return 0
}
run 2 6.2.1.3 "Kernel cmdline audit=1 + audit_backlog_limit [REBOOT-REQUIRED]" c_6_2_1_grub

# 6.2.2.2/6.2.2.3/6.2.2.4 — audit log retention and disk-full/error actions.
c_6_2_2() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if [[ ! -f /etc/audit/auditd.conf ]]; then
        SKIP_REASON="auditd not installed (no /etc/audit/auditd.conf)"
        return 0
    fi
    ensure_line /etc/audit/auditd.conf '^max_log_file_action[[:space:]]*=' \
        "max_log_file_action = keep_logs"
    ensure_line /etc/audit/auditd.conf '^disk_full_action[[:space:]]*=' \
        "disk_full_action = ${CIS_6_2_DISK_FULL_ACTION}"
    ensure_line /etc/audit/auditd.conf '^disk_error_action[[:space:]]*=' \
        "disk_error_action = ${CIS_6_2_DISK_ERROR_ACTION}"
    ensure_line /etc/audit/auditd.conf '^space_left_action[[:space:]]*=' \
        "space_left_action = ${CIS_6_2_SPACE_LEFT_ACTION}"
    ensure_line /etc/audit/auditd.conf '^admin_space_left_action[[:space:]]*=' \
        "admin_space_left_action = ${CIS_6_2_DISK_FULL_ACTION}"
}
run 2 6.2.2.3 "auditd retention + disk-full/error handling" c_6_2_2

# 6.2.3.x — audit rules. One managed file; augenrules loads it.
c_6_2_3() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if [[ ! -d /etc/audit/rules.d ]]; then
        SKIP_REASON="auditd not installed (no /etc/audit/rules.d)"
        return 0
    fi
    # Unquoted heredoc: only ${CIS_5_2_3_SUDO_LOGFILE} is expanded below.
    ensure_file_content /etc/audit/rules.d/60-cis.rules 0640 <<EOF
## Managed by CIS hardening — Section 6.2.3
## 6.2.3.1 — changes to system administration scope (sudoers)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
## 6.2.3.2 — actions as another user
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
## 6.2.3.3 — changes to the sudo log file (5.2.3)
-w ${CIS_5_2_3_SUDO_LOGFILE} -p wa -k sudo_log_file
## 6.2.3.4 — date and time modification
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
## 6.2.3.5 — hostname/domainname changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
## 6.2.3.6 — /etc/issue, /etc/issue.net
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
## 6.2.3.7 — /etc/hosts, /etc/hostname
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
## 6.2.3.8 — /etc/network, /etc/networks
-w /etc/network/ -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
## 6.2.3.9 — /etc/netplan
-w /etc/netplan/ -p wa -k system-locale
## 6.2.3.11/12/13 — user/group database modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
## 6.2.3.14 — /etc/security/opasswd
-w /etc/security/opasswd -p wa -k usergroup_modification
## 6.2.3.15 — /etc/nsswitch.conf
-w /etc/nsswitch.conf -p wa -k usergroup_modification
## 6.2.3.16 — /etc/pam.conf, /etc/pam.d
-w /etc/pam.conf -p wa -k usergroup_modification
-w /etc/pam.d/ -p wa -k usergroup_modification
## 6.2.3.17 — unsuccessful file access attempts
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
## 6.2.3.18 — DAC permission modification events
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
## 6.2.3.19 — successful file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
## 6.2.3.20 — session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
## 6.2.3.21 — login and logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
## 6.2.3.22 — file deletion events by users (incl. renameat2)
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k delete
## 6.2.3.23 — Mandatory Access Control (AppArmor) modifications
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
## 6.2.3.24 — chcon usage
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
## 6.2.3.27 — usermod usage
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod
## 6.2.3.28 — kernel module load/unload/modify
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
EOF
    (( CHANGED )) && notify auditd
    return 0
}
run 2 6.2.3 "CIS audit rules (60-cis.rules, b64+b32)" c_6_2_3

# 6.2.3.10 — privileged commands: one rule per setuid/setgid binary actually on
# disk, regenerated each run so package changes are picked up.
# [K8S-RISK][CONTAINER-RISK] container storage pruned via CIS_7_FS_SCAN_EXCLUDES.
c_6_2_3_10() {
    c_6_2_gate || { SKIP_REASON="disabled via CIS_6_2_MANAGE_AUDITD"; return 0; }
    if [[ ! -d /etc/audit/rules.d ]]; then
        SKIP_REASON="auditd not installed"
        return 0
    fi
    local tmp f
    tmp=$(mktemp)
    {
        echo "## Managed by CIS hardening — control 6.2.3.10 (auto-generated)"
        while IFS= read -r f; do
            printf -- '-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n' "$f"
        done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
                     "${CIS_FIND_EXCLUDES[@]}" 2>/dev/null | sort)
    } > "$tmp"
    ensure_file_content /etc/audit/rules.d/61-cis-privileged.rules 0640 < "$tmp"
    rm -f "$tmp"
    (( CHANGED )) && notify auditd
    return 0
}
# NOTE: the run call for 6.2.3.10 is at the END of this file so the generated
# rule list also covers binaries installed by later controls (e.g. AIDE).

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

# -----------------------------------------------------------------------------
# 6.3.x — AIDE file integrity monitoring
# -----------------------------------------------------------------------------
c_6_3_1() {
    if ! bool "$CIS_6_3_MANAGE_AIDE"; then
        SKIP_REASON="disabled via CIS_6_3_MANAGE_AIDE"
        return 0
    fi
    pkg_present aide aide-common
}
run 1 6.3.1 "AIDE installed" c_6_3_1

# 6.3.2 — integrity checked regularly (systemd timer) + database initialized.
c_6_3_2() {
    bool "$CIS_6_3_MANAGE_AIDE" || { SKIP_REASON="disabled via CIS_6_3_MANAGE_AIDE"; return 0; }
    command -v aide >/dev/null || command -v aide.wrapper >/dev/null \
        || { SKIP_REASON="aide not installed"; return 0; }
    # Exclude container/k8s storage from AIDE's file database — massive churn.
    if [[ -d /etc/aide/aide.conf.d ]]; then
        local p lines=""
        for p in "${CIS_7_FS_SCAN_EXCLUDES[@]}"; do
            [[ $p == /proc || $p == /sys ]] && continue
            lines+="!${p}"$'\n'
        done
        ensure_file_content /etc/aide/aide.conf.d/70_cis_excludes 0644 <<<"# Managed by CIS hardening — exclude container/k8s storage
${lines%$'\n'}"
    fi
    if systemctl list-unit-files dailyaidecheck.timer >/dev/null 2>&1 \
       && ! systemctl is-enabled dailyaidecheck.timer >/dev/null 2>&1; then
        CHANGED=1
        (( DRY_RUN )) || systemctl enable dailyaidecheck.timer >>"$LOG_FILE" 2>&1 || true
    fi
    if bool "$CIS_6_3_INIT_DB" && [[ ! -f /var/lib/aide/aide.db ]]; then
        CHANGED=1
        EXTRA_MSG="AIDE database initialized (first build can take minutes)"
        if (( ! DRY_RUN )); then
            aideinit -y -f >>"$LOG_FILE" 2>&1 || return 1
        fi
    fi
    return 0
}
run 1 6.3.2 "AIDE database + daily integrity check timer" c_6_3_2

# 6.3.3 — protect audit tool integrity via AIDE rules.
c_6_3_3() {
    bool "$CIS_6_3_MANAGE_AIDE" || { SKIP_REASON="disabled via CIS_6_3_MANAGE_AIDE"; return 0; }
    [[ -d /etc/aide/aide.conf.d ]] || { SKIP_REASON="aide not installed"; return 0; }
    ensure_file_content /etc/aide/aide.conf.d/70_cis_audit_tools 0644 <<'EOF'
# Managed by CIS hardening — control 6.3.3 (audit tool integrity)
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF
}
run 1 6.3.3 "AIDE rules protecting audit tools" c_6_3_3

# -----------------------------------------------------------------------------
# Deferred-to-last sweeps (see notes above): run after every other section 6
# control so files/binaries created THIS run are covered within the same run.
# -----------------------------------------------------------------------------
run 2 6.2.3.10 "Audit rules for all privileged (suid/sgid) commands" c_6_2_3_10
run 1 6.1.3.1 "Log file permissions (live sweep, 0640/0664 classes)" c_6_1_3_1
