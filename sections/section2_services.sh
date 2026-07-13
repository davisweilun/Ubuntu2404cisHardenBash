# =============================================================================
# Section 2 — Services   (CIS Ubuntu 24.04 Benchmark v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section2_services.yml.
# =============================================================================

# -----------------------------------------------------------------------------
# 2.1.x — Server services not in use (disable + purge)
# -----------------------------------------------------------------------------
c_pkg_purge_toggle() {
    # ARGS: package toggle-varname [risk-note]
    local pkg=$1 toggle=$2
    if ! bool "${!toggle}"; then
        SKIP_REASON="kept via $toggle=false"
        return 0
    fi
    pkg_absent "$pkg"
}

# [GUI-RISK] avahi provides .local mDNS discovery used by some desktops/printers.
run 1 2.1.3  "avahi daemon not in use"        c_pkg_purge_toggle avahi-daemon CIS_2_1_3_REMOVE_AVAHI
# [GUI-RISK] removes local printing. Keep on workstations that print.
run 1 2.1.14 "print server (cups) not in use" c_pkg_purge_toggle cups CIS_2_1_14_REMOVE_CUPS

# -----------------------------------------------------------------------------
# 2.2.x — Insecure client packages not installed
# -----------------------------------------------------------------------------
run 1 2.2.4 "telnet client removed" c_pkg_purge_toggle telnet CIS_2_2_4_REMOVE_TELNET_CLIENT
# [AD-RISK] ldap-utils (2.2.5): keep where admins run ldapsearch against AD/LDAP.
run 1 2.2.5 "ldap client (ldap-utils) removed" c_pkg_purge_toggle ldap-utils CIS_2_2_5_REMOVE_LDAP_CLIENT
run 1 2.2.6 "ftp client removed" c_pkg_purge_toggle ftp CIS_2_2_6_REMOVE_FTP_CLIENT

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
# 2.4.1.7 — /etc/cron.yearly owned root:root, mode 0700.
c_2_4_1_7() {
    ensure_dir /etc/cron.yearly 0700
}
run 1 2.4.1.7 "/etc/cron.yearly root:root 0700" c_2_4_1_7
