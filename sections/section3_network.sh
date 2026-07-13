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
run 1 3.2.1 "Blacklist atm kernel module"  c_3_2_module atm  3.2.1
run 1 3.2.2 "Blacklist can kernel module"  c_3_2_module can  3.2.2
run 1 3.2.3 "Blacklist dccp kernel module" c_3_2_module dccp 3.2.3
run 1 3.2.4 "Blacklist rds kernel module"  c_3_2_module rds  3.2.4
run 1 3.2.5 "Blacklist sctp kernel module" c_3_2_module sctp 3.2.5
run 1 3.2.6 "Blacklist tipc kernel module" c_3_2_module tipc 3.2.6

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

# 3.3.1.4/5 — Do not send ICMP redirects.
c_3_3_1_send_redirects() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.send_redirects=0 \
        net.ipv4.conf.default.send_redirects=0
}
run 1 3.3.1.4 "Do not send ICMP redirects" c_3_3_1_send_redirects

# 3.3.1.8/9 — Do not accept ICMP redirects.
c_3_3_1_accept_redirects() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.accept_redirects=0 \
        net.ipv4.conf.default.accept_redirects=0
}
run 1 3.3.1.9 "Do not accept ICMP redirects" c_3_3_1_accept_redirects

# 3.3.1.10/11 — Do not accept secure (gateway-listed) ICMP redirects.
c_3_3_1_secure_redirects() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.secure_redirects=0 \
        net.ipv4.conf.default.secure_redirects=0
}
run 1 3.3.1.10 "Do not accept secure ICMP redirects" c_3_3_1_secure_redirects

# 3.3.1.12/13 — Strict reverse-path filtering.
# [K8S-RISK] some CNIs (notably Calico) need loose rp_filter — toggle off there.
c_3_3_1_rp_filter() {
    if ! bool "$CIS_3_3_RP_FILTER_STRICT"; then
        SKIP_REASON="loose rp_filter kept (CIS_3_3_RP_FILTER_STRICT=false) [K8S-RISK]"
        return 0
    fi
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.rp_filter=1 \
        net.ipv4.conf.default.rp_filter=1
}
run 1 3.3.1.12 "Strict reverse-path filtering (rp_filter=1)" c_3_3_1_rp_filter

# 3.3.1.14/15 — Do not accept source-routed packets.
c_3_3_1_source_route() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.accept_source_route=0 \
        net.ipv4.conf.default.accept_source_route=0
}
run 1 3.3.1.14 "Do not accept source-routed packets" c_3_3_1_source_route

# 3.3.1.16/17 — Log martian packets.
c_3_3_1_martians() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf \
        net.ipv4.conf.all.log_martians=1 \
        net.ipv4.conf.default.log_martians=1
}
run 1 3.3.1.16 "Log martian packets" c_3_3_1_martians

# 3.3.1.18 — TCP SYN cookies.
c_3_3_1_syncookies() {
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv4.conf net.ipv4.tcp_syncookies=1
}
run 1 3.3.1.18 "TCP SYN cookies enabled" c_3_3_1_syncookies

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

# 3.3.2.7/8 — Do not accept IPv6 router advertisements (breaks SLAAC-configured
# IPv6; harmless where IPv6 is unused or statically/DHCPv6 configured).
c_3_3_2_accept_ra() {
    if ! bool "$CIS_3_3_MANAGE_IPV6"; then
        SKIP_REASON="disabled via CIS_3_3_MANAGE_IPV6"
        return 0
    fi
    c_sysctl_pairs /etc/sysctl.d/60-cis-net-ipv6.conf \
        net.ipv6.conf.all.accept_ra=0 \
        net.ipv6.conf.default.accept_ra=0
}
run 1 3.3.2.7 "Do not accept IPv6 router advertisements" c_3_3_2_accept_ra
