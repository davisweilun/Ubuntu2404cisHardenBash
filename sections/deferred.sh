# =============================================================================
# Deferred Controls — disruptive / reboot-required remediations
# =============================================================================
# Sourced by harden.sh ONLY when CIS_RUN_DEFERRED=true (or --deferred).
# These controls can disrupt a running host. Run deliberately, ideally in a
# maintenance window:
#   sudo ./harden.sh --deferred
# =============================================================================

# 1.1.1.10 — usb-storage: blacklist. Fully effective only after reboot; can
# disconnect live USB devices (keyboards on some servers, install media).
# [REBOOT-REQUIRED]
c_1_1_1_10() {
    if ! bool "$CIS_1_1_1_10_ENABLED"; then
        SKIP_REASON="disabled via CIS_1_1_1_10_ENABLED"
        return 0
    fi
    blacklist_module usb-storage "1.1.1.10 (deferred)"
    (( CHANGED )) && notify initramfs
    return 0
}
run 1 1.1.1.10 "Blacklist usb-storage kernel module [REBOOT-REQUIRED]" c_1_1_1_10

# 1.1.2.{1,3,4,5,6,7}.1 — Dedicated partitions for /tmp, /home, /var, /var/tmp,
# /var/log, /var/log/audit are OUT OF SCOPE: creating partitions requires
# repartitioning + reboot and must be done at image-build / provisioning time,
# not by configuration management on a running host. No task is generated.
