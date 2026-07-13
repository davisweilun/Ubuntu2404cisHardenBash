# =============================================================================
# Section 5 — Access, Authentication & Authorization  (CIS v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section5_access.yml.
#
# [AD-RISK] sshd/sudo changes can lock out accounts. PAM (5.3) is done via
# pam-auth-update PROFILES so it coexists with realm/SSSD AD integration — but
# still validate on a non-prod AD-joined host first. Recommended order on AD
# hosts: join the domain FIRST, then run this script, then test a domain
# login in a second session before logging out.
# =============================================================================

# -----------------------------------------------------------------------------
# 5.1.x — SSH server (drop-in keeps the main sshd_config pristine)
# -----------------------------------------------------------------------------
# 5.1.7 5.1.16 5.1.20 (L1); 5.1.15 MACs L1; 5.1.8 DisableForwarding L2.
# [AD-RISK] PermitRootLogin no: ensure a non-root sudo account exists first.
c_5_1_sshd() {
    if [[ ! -x /usr/sbin/sshd ]]; then
        SKIP_REASON="openssh-server not installed"
        return 0
    fi
    local f=/etc/ssh/sshd_config.d/60-cis.conf
    local content
    content="# Managed by CIS hardening — Section 5.1
PermitRootLogin ${CIS_5_1_PERMITROOTLOGIN}
MaxAuthTries ${CIS_5_1_16_MAXAUTHTRIES}
ClientAliveInterval ${CIS_5_1_7_CLIENTALIVEINTERVAL}
ClientAliveCountMax ${CIS_5_1_7_CLIENTALIVECOUNTMAX}
MACs ${CIS_5_1_MACS}"
    if bool "$CIS_5_1_8_DISABLEFORWARDING" && bool "$CIS_LEVEL2_ENABLED"; then
        content+=$'\n'"DisableForwarding yes"
    fi
    ensure_file_content "$f" 0600 <<<"$content"
    if (( CHANGED )) && (( ! DRY_RUN )); then
        # Validate the FULL sshd config with the drop-in in place; roll back on error.
        # sshd -t needs the privilege-separation dir, absent until ssh first starts.
        mkdir -p /run/sshd
        if ! /usr/sbin/sshd -t 2>>"$LOG_FILE"; then
            restore_file "$f"
            EXTRA_MSG="sshd -t rejected the new config; change rolled back"
            return 1
        fi
        notify sshd
    fi
    return 0
}
run 1 5.1 "sshd hardening drop-in (root login, MaxAuthTries, keepalive, MACs)" c_5_1_sshd

# -----------------------------------------------------------------------------
# 5.2.x — sudo / su
# -----------------------------------------------------------------------------
# 5.2.4 — users must authenticate for escalation (strip NOPASSWD). L2.
c_5_2_4() {
    if ! bool "$CIS_5_2_4_REQUIRE_PASSWORD"; then
        SKIP_REASON="disabled via CIS_5_2_4_REQUIRE_PASSWORD"
        return 0
    fi
    local f files=(/etc/sudoers) tmp fixed=0
    for f in /etc/sudoers.d/*; do
        [[ -f $f ]] && files+=("$f")
    done
    for f in "${files[@]}"; do
        grep -Eq '^[^#].*\bNOPASSWD[[:space:]]*:' "$f" || continue
        CHANGED=1
        (( DRY_RUN )) && continue
        tmp=$(mktemp)
        sed -E 's/^([^#].*)\bNOPASSWD[[:space:]]*:[[:space:]]*/\1/' "$f" > "$tmp"
        if visudo -cf "$tmp" >>"$LOG_FILE" 2>&1; then
            backup_file "$f"
            cat "$tmp" > "$f"   # cat keeps the original file's owner/mode
            fixed=$((fixed + 1))
        else
            rm -f "$tmp"
            EXTRA_MSG="edited $f failed visudo validation; left untouched"
            return 1
        fi
        rm -f "$tmp"
    done
    (( fixed )) && EXTRA_MSG="NOPASSWD stripped from $fixed file(s)"
    return 0
}
run 2 5.2.4 "sudo requires a password (strip NOPASSWD)" c_5_2_4

# 5.2.7 — restrict the su command to members of an (empty) group via pam_wheel.
c_5_2_7() {
    if ! getent group "$CIS_5_2_7_SU_GROUP" >/dev/null; then
        CHANGED=1
        (( DRY_RUN )) || groupadd "$CIS_5_2_7_SU_GROUP"
    fi
    local line="auth required pam_wheel.so use_uid group=${CIS_5_2_7_SU_GROUP}"
    if ! grep -Fxq "$line" /etc/pam.d/su; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            backup_file /etc/pam.d/su
            local tmp
            tmp=$(mktemp)
            # Insert after the commented pam_wheel example (keeps PAM stack order,
            # before the common-auth include); fall back to before common-auth.
            CIS_LINE="$line" awk '
                BEGIN { line = ENVIRON["CIS_LINE"]; done = 0 }
                { print }
                /^#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so/ && !done {
                    print line; done = 1
                }' /etc/pam.d/su > "$tmp"
            if ! grep -Fxq "$line" "$tmp"; then
                CIS_LINE="$line" awk '
                    BEGIN { line = ENVIRON["CIS_LINE"]; done = 0 }
                    /^@include[[:space:]]+common-auth/ && !done { print line; done = 1 }
                    { print }
                    END { if (!done) print line }' /etc/pam.d/su > "$tmp"
            fi
            cat "$tmp" > /etc/pam.d/su
            rm -f "$tmp"
        fi
    fi
    return 0
}
run 1 5.2.7 "Restrict su via pam_wheel + empty group" c_5_2_7

# -----------------------------------------------------------------------------
# 5.3.x — PAM: password quality, lockout, history
# -----------------------------------------------------------------------------
# 5.3.3.1.{1,2,3} — account lockout (pam_faillock).
c_5_3_3_1() {
    local content
    content="# Managed by CIS hardening — controls 5.3.3.1.1-5.3.3.1.3
deny = ${CIS_5_3_FAILLOCK_DENY}
unlock_time = ${CIS_5_3_FAILLOCK_UNLOCK_TIME}"
    if bool "$CIS_5_3_FAILLOCK_EVEN_DENY_ROOT"; then
        content+=$'\n'"even_deny_root"
    fi
    ensure_file_content /etc/security/faillock.conf 0644 <<<"$content"
}
run 1 5.3.3.1 "faillock.conf (lockout threshold/unlock time)" c_5_3_3_1

# 5.3.3.2.{1,2,4,5,8} — password quality (pam_pwquality).
c_5_3_3_2() {
    ensure_dir /etc/security/pwquality.conf.d 0755
    ensure_file_content /etc/security/pwquality.conf.d/60-cis.conf 0644 <<EOF
# Managed by CIS hardening — controls 5.3.3.2.x
minlen = ${CIS_5_3_PWQUALITY_MINLEN}
difok = ${CIS_5_3_PWQUALITY_DIFOK}
maxrepeat = ${CIS_5_3_PWQUALITY_MAXREPEAT}
maxsequence = ${CIS_5_3_PWQUALITY_MAXSEQUENCE}
enforce_for_root
EOF
}
run 1 5.3.3.2 "pwquality.conf (minlen/difok/maxrepeat/maxsequence)" c_5_3_3_2

# 5.3.3.3.{1,2} — pam_pwhistory settings.
c_5_3_3_3() {
    ensure_file_content /etc/security/pwhistory.conf 0644 <<EOF
# Managed by CIS hardening — controls 5.3.3.3.1, 5.3.3.3.2
remember = ${CIS_5_3_PWHISTORY_REMEMBER}
enforce_for_root
EOF
}
run 1 5.3.3.3 "pwhistory.conf (remember=${CIS_5_3_PWHISTORY_REMEMBER})" c_5_3_3_3

# 5.3.2.2 / 5.3.2.4 / 5.3.3.4.1 — enable PAM modules the supported, AD/SSSD-safe
# way: register pam-auth-update PROFILES (never edit common-* directly).
# pam-auth-update merges these with the sss profile that `realm join` installs,
# so domain logins keep working. Module *settings* live in the .conf files above.
c_5_3_pam_profiles() {
    if ! bool "$CIS_5_3_MANAGE_PAM"; then
        SKIP_REASON="disabled via CIS_5_3_MANAGE_PAM"
        return 0
    fi
    local p
    for p in cis_faillock cis_faillock_notify cis_pwhistory; do
        if [[ ! -r "$SCRIPT_DIR/files/pam-configs/$p" ]]; then
            EXTRA_MSG="repo file files/pam-configs/$p missing"
            return 1
        fi
        ensure_file_content "/usr/share/pam-configs/$p" 0644 \
            < "$SCRIPT_DIR/files/pam-configs/$p"
    done

    # 5.3.3.4.1 — remove nullok from the stock unix profile so the regenerated
    # common-auth/common-password no longer permit blank passwords.
    if [[ -f /usr/share/pam-configs/unix ]] && grep -Eq '[[:space:]]nullok\b' /usr/share/pam-configs/unix; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            backup_file /usr/share/pam-configs/unix
            sed -E -i 's/([[:space:]])nullok\b/\1/g' /usr/share/pam-configs/unix
        fi
    fi

    # Apply immediately (Ansible: flush_handlers) so the rest of the run — and
    # any reboot — sees a consistent common-* stack.
    if (( CHANGED )) && (( ! DRY_RUN )); then
        if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --package >>"$LOG_FILE" 2>&1; then
            EXTRA_MSG="pam-auth-update --package failed"
            return 1
        fi
        EXTRA_MSG="pam-auth-update applied"
    fi
    return 0
}
run 1 5.3.2 "PAM faillock/pwhistory/no-nullok via pam-auth-update profiles [AD-RISK]" c_5_3_pam_profiles

# -----------------------------------------------------------------------------
# 5.4.x — User accounts and environment
# -----------------------------------------------------------------------------
# 5.4.1.1 / 5.4.1.3 — password aging in login.defs.
c_5_4_1_1() {
    ensure_line /etc/login.defs '^#?[[:space:]]*PASS_MAX_DAYS[[:space:]]' \
        "$(printf 'PASS_MAX_DAYS\t%s' "$CIS_5_4_PASS_MAX_DAYS")"
    ensure_line /etc/login.defs '^#?[[:space:]]*PASS_WARN_AGE[[:space:]]' \
        "$(printf 'PASS_WARN_AGE\t%s' "$CIS_5_4_PASS_WARN_AGE")"
}
run 1 5.4.1.1 "Password aging in /etc/login.defs" c_5_4_1_1

# 5.4.1.5 — inactive password lock (new accounts).
c_5_4_1_5() {
    local cur
    cur=$(useradd -D | awk -F= '/^INACTIVE=/{print $2}')
    [[ $cur == "$CIS_5_4_INACTIVE_LOCK_DAYS" ]] && return 0
    CHANGED=1
    (( DRY_RUN )) && return 0
    useradd -D -f "$CIS_5_4_INACTIVE_LOCK_DAYS" >>"$LOG_FILE" 2>&1
}
run 1 5.4.1.5 "Default inactive password lock (INACTIVE=${CIS_5_4_INACTIVE_LOCK_DAYS})" c_5_4_1_5

# 5.4.3.2 — shell timeout (TMOUT). 5.4.3.3 — default umask.
c_5_4_3() {
    ensure_file_content /etc/profile.d/60-cis-shell.sh 0644 <<EOF
# Managed by CIS hardening — controls 5.4.3.2, 5.4.3.3
TMOUT=${CIS_5_4_SHELL_TIMEOUT}
readonly TMOUT
export TMOUT
umask ${CIS_5_4_DEFAULT_UMASK}
EOF
}
run 1 5.4.3.2 "Shell timeout (TMOUT) and default umask" c_5_4_3
