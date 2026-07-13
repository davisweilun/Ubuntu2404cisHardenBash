# =============================================================================
# Section 3 — Network   (CIS Ubuntu 24.04 Benchmark v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section3_network.yml.
# =============================================================================

# -----------------------------------------------------------------------------
# 3.1.x — Network devices
# -----------------------------------------------------------------------------
# [GUI-RISK] disable on servers; keep on laptops/workstations using Bluetooth.
c_3_1_3() {
    if ! bool "$CIS_3_1_3_DISABLE_BLUETOOTH"; then
        SKIP_REASON="kept via CIS_3_1_3_DISABLE_BLUETOOTH=false"
        return 0
    fi
    pkg_absent bluez
}
run 1 3.1.3 "bluetooth services not in use (bluez removed)" c_3_1_3

# -----------------------------------------------------------------------------
# 3.2.x — Unused network protocol kernel modules
# -----------------------------------------------------------------------------
c_3_2_module() {
    blacklist_module "$1" "$2"
}
run 1 3.2.1 "Blacklist atm kernel module" c_3_2_module atm 3.2.1
run 1 3.2.2 "Blacklist can kernel module" c_3_2_module can 3.2.2

# -----------------------------------------------------------------------------
# 3.3.x — Kernel network parameters (sysctl)
# -----------------------------------------------------------------------------
c_sysctl_pairs() {
    # ARGS: dropin-file key=value ...
    local file=$1 kv
    shift
    for kv in "$@"; do
        ensure_sysctl "$file" "${kv%%=*}" "${kv#*=}"
    done
}

# 3.3.1.{1,2,3} — Disable IPv4 forwarding/routing. OPT-IN:
# [K8S-RISK][CONTAINER-RISK] Docker/containerd/Kubernetes/routers REQUIRE
# forwarding=1 — these controls stay non-compliant by choice on such hosts.
c_3_3_1_fwd() {
    if ! bool "$CIS_3_3_DISABLE_IP_FORWARDING"; then
        SKIP_REASON="left enabled by choice (CIS_3_3_DISABLE_IP_FORWARDING=false) [K8S-RISK][CONTAINER-RISK]"
        return 0
    fi
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-forwarding.conf \
        net.ipv4.ip_forward=0 \
        net.ipv4.conf.all.forwarding=0 \
        net.ipv4.conf.default.forwarding=0
}
run 1 3.3.1.1 "Disable IPv4 forwarding (opt-in)" c_3_3_1_fwd

# 3.3.1.16/17 — Log martian packets.
c_3_3_1_martians() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.log_martians=1 \
        net.ipv4.conf.default.log_martians=1
}
run 1 3.3.1.16 "Log martian packets" c_3_3_1_martians

# 3.3.2.{1-6} — IPv6 hardening: no forwarding, redirects, source routing.
# [K8S-RISK] ipv6 forwarding also affects dual-stack container networking.
c_3_3_2_ipv6() {
    if ! bool "$CIS_3_3_MANAGE_IPV6"; then
        SKIP_REASON="disabled via CIS_3_3_MANAGE_IPV6"
        return 0
    fi
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv6.conf \
        net.ipv6.conf.all.forwarding=0 \
        net.ipv6.conf.default.forwarding=0 \
        net.ipv6.conf.all.accept_redirects=0 \
        net.ipv6.conf.default.accept_redirects=0 \
        net.ipv6.conf.all.accept_source_route=0 \
        net.ipv6.conf.default.accept_source_route=0
}
run 1 3.3.2 "Harden IPv6 network parameters" c_3_3_2_ipv6
