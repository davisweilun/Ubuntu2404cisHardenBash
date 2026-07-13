# =============================================================================
# Section 4 — Host-Based Firewall (ufw)   (CIS Ubuntu 24.04 v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section4_firewall.yml.
#
# OFF BY DEFAULT (CIS_4_MANAGE_UFW=false). Many environments delegate the host
# firewall to a separate/third-party product; running ufw alongside it causes
# conflicting iptables rules. Set CIS_4_MANAGE_UFW=true ONLY where ufw is the
# intended host firewall.
#
# LOCKOUT SAFETY: the allow rule for the SSH port is added BEFORE the default
# deny policy and before enabling ufw. Confirm CIS_4_SSH_PORT matches sshd.
# This is the single most dangerous section to run on a remote host.
# =============================================================================

if ! bool "$CIS_4_MANAGE_UFW"; then
    record "4.1.x" SKIP "ufw management off by default (CIS_4_MANAGE_UFW=false) — [LOCKOUT-RISK], see config/hardening.conf"
else

c_4_1_1() {
    pkg_present ufw
}
run 1 4.1.1 "ufw installed" c_4_1_1

# Allow SSH FIRST so enabling the firewall cannot lock out this session.
c_4_1_2_allow_ssh() {
    command -v ufw >/dev/null || { SKIP_REASON="ufw not installed"; return 0; }
    if ufw status 2>/dev/null | grep -qE "^${CIS_4_SSH_PORT}/tcp[[:space:]]+ALLOW" \
       || ufw show added 2>/dev/null | grep -qE "^ufw allow ${CIS_4_SSH_PORT}/tcp\b"; then
        return 0
    fi
    CHANGED=1
    (( DRY_RUN )) && return 0
    ufw allow "${CIS_4_SSH_PORT}/tcp" >>"$LOG_FILE" 2>&1
}
run 1 4.1.2 "Allow SSH port ${CIS_4_SSH_PORT}/tcp before enabling firewall (anti-lockout)" c_4_1_2_allow_ssh

# 4.1.3 — default deny incoming. 4.1.5 — default deny routed.
c_4_default_policy() {
    # ARGS: direction policy
    local dir=$1 pol=$2
    command -v ufw >/dev/null || { SKIP_REASON="ufw not installed"; return 0; }
    if ufw status verbose 2>/dev/null | grep -i '^Default:' | grep -qi "${pol} (${dir})"; then
        return 0
    fi
    CHANGED=1
    (( DRY_RUN )) && return 0
    ufw default "$pol" "$dir" >>"$LOG_FILE" 2>&1
}
run 1 4.1.3 "Default deny incoming" c_4_default_policy incoming deny
run 1 4.1.5 "Default deny routed"   c_4_default_policy routed deny

# 4.1.4 — default deny outgoing (L2). OFF by default: deny-all outbound breaks
# DNS/NTP/updates unless every egress is explicitly allowed first.
c_4_1_4() {
    if ! bool "$CIS_4_1_4_OUTGOING_DENY"; then
        SKIP_REASON="opt-in, off by default (CIS_4_1_4_OUTGOING_DENY=false) — breaks egress"
        return 0
    fi
    c_4_default_policy outgoing deny
}
run 2 4.1.4 "Default deny outgoing (opt-in)" c_4_1_4

# 4.1.2 — enable + persist the firewall (done LAST, after policies/allow rules).
c_4_enable() {
    command -v ufw >/dev/null || { SKIP_REASON="ufw not installed"; return 0; }
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        return 0
    fi
    CHANGED=1
    (( DRY_RUN )) && return 0
    ufw --force enable >>"$LOG_FILE" 2>&1
}
run 1 4.1.2 "Enable and persist ufw [LOCKOUT-RISK]" c_4_enable

fi  # CIS_4_MANAGE_UFW
