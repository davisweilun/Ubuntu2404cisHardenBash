# =============================================================================
# Section 2 — Services   (CIS Ubuntu 24.04 Benchmark v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section2_services.yml.
# =============================================================================

# -----------------------------------------------------------------------------
# 2.1.x — Server services not in use (disable + purge)
# -----------------------------------------------------------------------------
c_pkg_purge_toggle() {
    # ARGS: toggle-varname package [package...]
    local toggle=$1
    shift
    if ! bool "${!toggle}"; then
        SKIP_REASON="kept via $toggle=false"
        return 0
    fi
    pkg_absent "$@"
}

# [GUI-RISK] avahi provides .local mDNS discovery used by some desktops/printers.
run 1 2.1.3  "avahi daemon not in use"        c_pkg_purge_toggle CIS_2_1_3_REMOVE_AVAHI avahi-daemon
# [GUI-RISK] removes local printing. Keep on workstations that print.
run 1 2.1.14 "print server (cups) not in use" c_pkg_purge_toggle CIS_2_1_14_REMOVE_CUPS cups

# -----------------------------------------------------------------------------
# 2.2.x — Insecure client packages not installed
# -----------------------------------------------------------------------------
# The audit also checks the alternate implementations (inetutils-*, tnftp).
run 1 2.2.4 "telnet clients removed (telnet, inetutils-telnet)" \
    c_pkg_purge_toggle CIS_2_2_4_REMOVE_TELNET_CLIENT telnet inetutils-telnet
# [AD-RISK] ldap-utils (2.2.5): keep where admins run ldapsearch against AD/LDAP.
run 1 2.2.5 "ldap client (ldap-utils) removed" c_pkg_purge_toggle CIS_2_2_5_REMOVE_LDAP_CLIENT ldap-utils
run 1 2.2.6 "ftp clients removed (ftp, tnftp)" \
    c_pkg_purge_toggle CIS_2_2_6_REMOVE_FTP_CLIENT ftp tnftp

# -----------------------------------------------------------------------------
# 2.3.x — Time synchronization
# -----------------------------------------------------------------------------
# 2.3.2.1 — systemd-timesyncd points at authorized timeservers.
c_2_3_2_1() {
    if ! bool "$CIS_2_3_MANAGE_TIMESYNCD"; then
        SKIP_REASON="disabled via CIS_2_3_MANAGE_TIMESYNCD (chrony/other manages time?)"
        return 0
    fi
    ensure_dir /etc/systemd/timesyncd.conf.d 0755
    ensure_file_content /etc/systemd/timesyncd.conf.d/60-cis.conf 0644 <<EOF
# Managed by CIS hardening — control 2.3.2.1
[Time]
NTP=${CIS_2_3_NTP_SERVERS}
FallbackNTP=${CIS_2_3_NTP_FALLBACK}
EOF
    (( CHANGED )) && notify timesyncd
    return 0
}
run 1 2.3.2.1 "systemd-timesyncd authorized timeservers" c_2_3_2_1

# -----------------------------------------------------------------------------
# 2.4.x — Job schedulers (cron)
# -----------------------------------------------------------------------------
# 2.4.1.2 — /etc/crontab root:root 0600.
c_2_4_1_2() {
    [[ -f /etc/crontab ]] || { SKIP_REASON="cron not installed"; return 0; }
    ensure_perms /etc/crontab 0600 root root
}
run 1 2.4.1.2 "/etc/crontab root:root 0600" c_2_4_1_2

# 2.4.1.3-2.4.1.8 — cron directories root:root 0700.
c_cron_dir() {
    [[ -d $1 ]] || { SKIP_REASON="$1 does not exist"; return 0; }
    ensure_dir "$1" 0700
}
run 1 2.4.1.3 "/etc/cron.hourly root:root 0700"  c_cron_dir /etc/cron.hourly
run 1 2.4.1.4 "/etc/cron.daily root:root 0700"   c_cron_dir /etc/cron.daily
run 1 2.4.1.5 "/etc/cron.weekly root:root 0700"  c_cron_dir /etc/cron.weekly
run 1 2.4.1.6 "/etc/cron.monthly root:root 0700" c_cron_dir /etc/cron.monthly
run 1 2.4.1.7 "/etc/cron.yearly root:root 0700"  c_cron_dir /etc/cron.yearly
run 1 2.4.1.8 "/etc/cron.d root:root 0700"       c_cron_dir /etc/cron.d

# 2.4.1.9 — restrict crontab to authorized users via /etc/cron.allow.
# Users not listed can no longer edit their crontabs.
c_2_4_1_9() {
    if ! bool "$CIS_2_4_1_9_MANAGE_CRON_ALLOW"; then
        SKIP_REASON="disabled via CIS_2_4_1_9_MANAGE_CRON_ALLOW"
        return 0
    fi
    local u content=""
    for u in $CIS_2_4_CRON_ALLOW_USERS; do
        content+="$u"$'\n'
    done
    ensure_file_content /etc/cron.allow 0640 <<<"${content%$'\n'}"
    # cron.deny is ignored once cron.allow exists; still tighten it if present.
    ensure_perms /etc/cron.deny 0640 root root
}
run 1 2.4.1.9 "crontab restricted via /etc/cron.allow" c_2_4_1_9
