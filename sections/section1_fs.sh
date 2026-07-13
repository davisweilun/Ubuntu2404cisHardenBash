# =============================================================================
# Section 1 — Initial Setup   (CIS Ubuntu 24.04 Benchmark v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section1_fs.yml.
# Controls requiring reboot/partitioning/console policy are NOT here:
#   - 1.1.1.10 usb-storage, 1.1.2.* partitions -> sections/deferred.sh
#   - 1.4.1 bootloader password                -> manual review
# =============================================================================

# -----------------------------------------------------------------------------
# 1.1.1.x — Disable unused filesystem / storage kernel modules
# -----------------------------------------------------------------------------
# Blacklist + disable autoload (no force-unload; effective fully after reboot).
# Validation: `modprobe -n -v <m>` -> 'install /bin/true'; `lsmod | grep <m>` empty.
c_module_blacklist() {
    # ARGS: module-name control-id toggle-varname
    local name=$1 control=$2 toggle=$3
    if ! bool "${!toggle}"; then
        SKIP_REASON="disabled via $toggle"
        return 0
    fi
    blacklist_module "$name" "$control"
}

# [CONTAINER-RISK] squashfs (1.1.1.7): snapd mounts snaps via squashfs — set
# CIS_1_1_1_7_ENABLED=false on snap-using hosts.
run 1 1.1.1.1 "Blacklist cramfs kernel module"        c_module_blacklist cramfs        1.1.1.1 CIS_1_1_1_1_ENABLED
run 1 1.1.1.2 "Blacklist freevxfs kernel module"      c_module_blacklist freevxfs      1.1.1.2 CIS_1_1_1_2_ENABLED
run 1 1.1.1.3 "Blacklist hfs kernel module"           c_module_blacklist hfs           1.1.1.3 CIS_1_1_1_3_ENABLED
run 1 1.1.1.4 "Blacklist hfsplus kernel module"       c_module_blacklist hfsplus       1.1.1.4 CIS_1_1_1_4_ENABLED
run 1 1.1.1.5 "Blacklist jffs2 kernel module"         c_module_blacklist jffs2         1.1.1.5 CIS_1_1_1_5_ENABLED
run 2 1.1.1.7 "Blacklist squashfs kernel module [CONTAINER-RISK]" c_module_blacklist squashfs 1.1.1.7 CIS_1_1_1_7_ENABLED
run 2 1.1.1.8 "Blacklist udf kernel module"           c_module_blacklist udf           1.1.1.8 CIS_1_1_1_8_ENABLED
run 1 1.1.1.9 "Blacklist firewire-core kernel module" c_module_blacklist firewire-core 1.1.1.9 CIS_1_1_1_9_ENABLED

# 1.1.1.6 overlay — opt-in only; overlay backs Docker/containerd/Kubernetes/snap.
# [CONTAINER-RISK][K8S-RISK] disabling overlay breaks all container runtimes.
c_1_1_1_6() {
    if ! bool "$CIS_1_1_1_6_OVERLAY_DISABLE"; then
        SKIP_REASON="opt-in, off by default (CIS_1_1_1_6_OVERLAY_DISABLE=false) [CONTAINER-RISK]"
        return 0
    fi
    blacklist_module overlay 1.1.1.6
}
run 2 1.1.1.6 "Blacklist overlay kernel module (opt-in)" c_1_1_1_6

# -----------------------------------------------------------------------------
# 1.1.2.x — Filesystem mount options (separate partitions are OUT OF SCOPE)
# -----------------------------------------------------------------------------
c_1_1_2_dev_shm() {
    if ! bool "$CIS_1_1_2_MANAGE_MOUNT_OPTS"; then
        SKIP_REASON="disabled via CIS_1_1_2_MANAGE_MOUNT_OPTS"
        return 0
    fi
    ensure_fstab_entry /dev/shm tmpfs tmpfs "$CIS_DEV_SHM_MOUNT_OPTS"
}
run 1 1.1.2.2 "nodev,nosuid,noexec on /dev/shm" c_1_1_2_dev_shm

c_1_1_2_tmp() {
    if ! bool "$CIS_1_1_2_MANAGE_MOUNT_OPTS"; then
        SKIP_REASON="disabled via CIS_1_1_2_MANAGE_MOUNT_OPTS"
        return 0
    fi
    if ! mountpoint -q /tmp; then
        SKIP_REASON="/tmp is not a separate mount (partitioning is provisioning-time, out of scope)"
        return 0
    fi
    local src fstype
    src=$(findmnt -no SOURCE /tmp)
    fstype=$(findmnt -no FSTYPE /tmp)
    ensure_fstab_entry /tmp "$src" "$fstype" "$CIS_TMP_MOUNT_OPTS"
}
run 1 1.1.2.1 "nodev,nosuid,noexec on /tmp (if separate mount)" c_1_1_2_tmp

# -----------------------------------------------------------------------------
# 1.2.x — Package management
# -----------------------------------------------------------------------------
# 1.2.1.2 — Weak dependencies disabled. Reduces installed surface.
c_1_2_1_2() {
    if ! bool "$CIS_1_2_1_2_DISABLE_WEAK_DEPS"; then
        SKIP_REASON="disabled via CIS_1_2_1_2_DISABLE_WEAK_DEPS"
        return 0
    fi
    # CIS-CAT requires the literal value "0" (not "false").
    ensure_file_content /etc/apt/apt.conf.d/99cis-no-weak-deps 0644 <<'EOF'
# Managed by CIS hardening — control 1.2.1.2
APT::Install-Recommends "0";
APT::Install-Suggests "0";
EOF
}
run 2 1.2.1.2 "Disable APT weak dependencies (Recommends/Suggests)" c_1_2_1_2

# -----------------------------------------------------------------------------
# 1.3.x — AppArmor (Mandatory Access Control)
# -----------------------------------------------------------------------------
c_1_3_1_1() {
    if ! bool "$CIS_1_3_APPARMOR_ENABLED"; then
        SKIP_REASON="disabled via CIS_1_3_APPARMOR_ENABLED"
        return 0
    fi
    pkg_present apparmor apparmor-utils
}
run 1 1.3.1.1 "AppArmor packages installed" c_1_3_1_1

# 1.3.1.4 — apparmor_restrict_unprivileged_unconfined enabled.
c_1_3_1_4() {
    if ! bool "$CIS_1_3_APPARMOR_ENABLED" || ! bool "$CIS_1_3_1_4_RESTRICT_UNPRIVILEGED"; then
        SKIP_REASON="disabled via toggle"
        return 0
    fi
    ensure_sysctl /etc/sysctl.d/60-cis-1.3.1.4.conf \
        kernel.apparmor_restrict_unprivileged_unconfined 1
}
run 1 1.3.1.4 "Restrict unprivileged unconfined (kernel sysctl)" c_1_3_1_4

# 1.3.1.3 — All AppArmor profiles enforcing (L2). Opt-in.
# [K8S-RISK][CONTAINER-RISK] enforcing all profiles can break workloads.
c_1_3_1_3() {
    if ! bool "$CIS_1_3_APPARMOR_ENABLED" || ! bool "$CIS_1_3_1_3_ENFORCE_PROFILES"; then
        SKIP_REASON="opt-in, off by default (CIS_1_3_1_3_ENFORCE_PROFILES=false) [K8S-RISK][CONTAINER-RISK]"
        return 0
    fi
    command -v aa-enforce >/dev/null || { SKIP_REASON="aa-enforce not available"; return 0; }
    if (( DRY_RUN )); then
        CHANGED=1
        EXTRA_MSG="would run aa-enforce on all profiles"
        return 0
    fi
    local out
    out=$(aa-enforce /etc/apparmor.d/* 2>>"$LOG_FILE") || return 1
    [[ $out == *Setting* ]] && CHANGED=1
}
run 2 1.3.1.3 "Set all AppArmor profiles to enforce mode (opt-in)" c_1_3_1_3

# -----------------------------------------------------------------------------
# 1.5.x — Kernel / process hardening
# -----------------------------------------------------------------------------
c_1_5_5() {
    if ! bool "$CIS_1_5_5_DMESG_RESTRICT"; then
        SKIP_REASON="disabled via CIS_1_5_5_DMESG_RESTRICT"
        return 0
    fi
    ensure_sysctl /etc/sysctl.d/60-cis-1.5.5.conf kernel.dmesg_restrict 1
}
run 1 1.5.5 "kernel.dmesg_restrict = 1" c_1_5_5

# 1.5.4 — fs.suid_dumpable = 0 (no core dumps from setuid programs).
c_1_5_4() {
    ensure_sysctl /etc/sysctl.d/60-cis-1.5.4.conf fs.suid_dumpable 0
}
run 1 1.5.4 "fs.suid_dumpable = 0" c_1_5_4

# 1.5.9 — ASLR. Runtime default is already 2, but the benchmark requires the
# value to be pinned in a sysctl config file.
c_1_5_9() {
    ensure_sysctl /etc/sysctl.d/60-cis-1.5.9.conf kernel.randomize_va_space 2
}
run 1 1.5.9 "kernel.randomize_va_space = 2" c_1_5_9

# 1.5.6 — prelink not installed (interferes with ASLR / integrity).
c_1_5_6() {
    if ! bool "$CIS_1_5_6_PRELINK_REMOVE"; then
        SKIP_REASON="disabled via CIS_1_5_6_PRELINK_REMOVE"
        return 0
    fi
    pkg_absent prelink
}
run 1 1.5.6 "prelink not installed" c_1_5_6

# 1.5.7 — Automatic Error Reporting (apport) disabled.
c_1_5_7() {
    if ! bool "$CIS_1_5_7_DISABLE_APPORT"; then
        SKIP_REASON="disabled via CIS_1_5_7_DISABLE_APPORT"
        return 0
    fi
    ensure_line /etc/default/apport '^enabled=' 'enabled=0'
    (( CHANGED )) && notify apport
    return 0
}
run 1 1.5.7 "Disable Automatic Error Reporting (apport)" c_1_5_7

# -----------------------------------------------------------------------------
# 1.6.x — Command-line warning banners
# -----------------------------------------------------------------------------
# 1.6.1 — /etc/motd present without OS escapes (\m \r \s \v).
c_1_6_1() {
    if ! bool "$CIS_1_6_MANAGE_BANNERS"; then
        SKIP_REASON="disabled via CIS_1_6_MANAGE_BANNERS"
        return 0
    fi
    ensure_file_content /etc/motd 0644 <<EOF
${CIS_1_6_BANNER_TEXT}
EOF
}
run 1 1.6.1 "Configure /etc/motd warning banner" c_1_6_1

# 1.6.2 / 1.6.3 — /etc/issue and /etc/issue.net: same clean banner, no OS info.
# issue.net doubles as the sshd Banner file (5.1.5 / 1.6.5 / 1.6.10).
c_1_6_2() {
    if ! bool "$CIS_1_6_MANAGE_BANNERS"; then
        SKIP_REASON="disabled via CIS_1_6_MANAGE_BANNERS"
        return 0
    fi
    ensure_file_content /etc/issue 0644 <<EOF
${CIS_1_6_BANNER_TEXT}
EOF
}
run 1 1.6.2 "Configure /etc/issue warning banner" c_1_6_2

c_1_6_3() {
    if ! bool "$CIS_1_6_MANAGE_BANNERS"; then
        SKIP_REASON="disabled via CIS_1_6_MANAGE_BANNERS"
        return 0
    fi
    ensure_file_content /etc/issue.net 0644 <<EOF
${CIS_1_6_BANNER_TEXT}
EOF
}
run 1 1.6.3 "Configure /etc/issue.net warning banner (sshd Banner file)" c_1_6_3

# 1.6.1 / 1.6.4 — pam_motd: Ubuntu's dynamic MOTD scripts print OS/patch info
# at login (the scanner flags each script). Remove their execute bit and keep
# motd-news off. Reversible with chmod +x.
c_1_6_4() {
    if ! bool "$CIS_1_6_MANAGE_BANNERS"; then
        SKIP_REASON="disabled via CIS_1_6_MANAGE_BANNERS"
        return 0
    fi
    ensure_line /etc/default/motd-news '^ENABLED=' 'ENABLED=0'
    if bool "$CIS_1_6_DISABLE_DYNAMIC_MOTD" && [[ -d /etc/update-motd.d ]]; then
        local f n=0
        for f in /etc/update-motd.d/*; do
            [[ -f $f && -x $f ]] || continue
            CHANGED=1
            n=$((n + 1))
            (( DRY_RUN )) || chmod -x "$f"
        done
        (( n )) && EXTRA_MSG="$n dynamic MOTD script(s) disabled"
    fi
    return 0
}
run 1 1.6.4 "Disable dynamic MOTD (motd-news + update-motd.d scripts)" c_1_6_4

# 1.6.6-1.6.10 — Permissions on banner files (root:root 0644).
c_1_6_perms() {
    local f
    for f in /etc/motd /etc/issue /etc/issue.net; do
        ensure_perms "$f" 0644 root root
    done
}
run 1 1.6.6 "Permissions on /etc/motd, /etc/issue, /etc/issue.net" c_1_6_perms

# -----------------------------------------------------------------------------
# 1.7.x — GDM (only on graphical hosts; self-skips when dconf is absent)
# -----------------------------------------------------------------------------
c_1_7_gdm() {
    if ! bool "$CIS_HOST_HAS_GUI" || ! bool "$CIS_1_7_MANAGE_GDM"; then
        SKIP_REASON="no GUI on this host / disabled via toggle"
        return 0
    fi
    if ! command -v dconf >/dev/null; then
        SKIP_REASON="dconf not installed (no GNOME/GDM on this host)"
        return 0
    fi
    ensure_dir /etc/dconf/db/gdm.d 0755
    ensure_dir /etc/dconf/db/gdm.d/locks 0755
    ensure_dir /etc/dconf/profile 0755

    ensure_file_content /etc/dconf/profile/gdm 0644 <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

    # 1.7.1 banner, 1.7.2 disable-user-list, 1.7.3 screen lock,
    # 1.7.4 automount off, 1.7.5 autorun-never.
    ensure_file_content /etc/dconf/db/gdm.d/00-cis-hardening 0644 <<EOF
# Managed by CIS hardening — controls 1.7.1-1.7.5
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${CIS_1_6_BANNER_TEXT}'
disable-user-list=true

[org/gnome/desktop/session]
idle-delay=uint32 ${CIS_1_7_SCREENSAVER_IDLE_DELAY}

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 ${CIS_1_7_SCREENSAVER_LOCK_DELAY}

[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
EOF

    ensure_file_content /etc/dconf/db/gdm.d/locks/00-cis-locks 0644 <<'EOF'
# Managed by CIS hardening — prevent users overriding 1.7.x settings
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/autorun-never
EOF

    (( CHANGED )) && notify dconf
    return 0
}
run 1 1.7 "GDM hardening (banner, user list, screen lock, automount)" c_1_7_gdm
