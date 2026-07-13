# =============================================================================
# Section 7 — System Maintenance   (CIS Ubuntu 24.04 v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section7_system.yml.
# =============================================================================

# Build the shared `find` pruning arguments from CIS_7_FS_SCAN_EXCLUDES.
# Keeps the recursive sweeps below from touching container/k8s storage.
# [K8S-RISK][CONTAINER-RISK] see config/hardening.conf.
CIS_FIND_EXCLUDES=()
for _p in "${CIS_7_FS_SCAN_EXCLUDES[@]}"; do
    CIS_FIND_EXCLUDES+=(-not -path "${_p}/*")
done
unset _p

# -----------------------------------------------------------------------------
# 7.1.x — Filesystem permissions
# -----------------------------------------------------------------------------
# 7.1.11 — world-writable files/dirs secured (strip o+w; add sticky bit to dirs).
c_7_1_11() {
    if ! bool "$CIS_7_1_11_FIX_WORLD_WRITABLE"; then
        SKIP_REASON="disabled via CIS_7_1_11_FIX_WORLD_WRITABLE"
        return 0
    fi
    local files=() dirs=() f
    mapfile -t files < <(find / -xdev -type f -perm -0002 "${CIS_FIND_EXCLUDES[@]}" 2>/dev/null)
    mapfile -t dirs  < <(find / -xdev -type d -perm -0002 -not -perm -1000 "${CIS_FIND_EXCLUDES[@]}" 2>/dev/null)
    if (( ${#files[@]} == 0 && ${#dirs[@]} == 0 )); then
        return 0
    fi
    CHANGED=1
    EXTRA_MSG="${#files[@]} world-writable file(s) o-w, ${#dirs[@]} dir(s) +t"
    (( DRY_RUN )) && return 0
    for f in "${files[@]}"; do
        chmod o-w "$f" 2>>"$LOG_FILE" || true
        printf '7.1.11 o-w: %s\n' "$f" >>"$LOG_FILE"
    done
    for f in "${dirs[@]}"; do
        chmod +t "$f" 2>>"$LOG_FILE" || true
        printf '7.1.11 +t: %s\n' "$f" >>"$LOG_FILE"
    done
    return 0
}
run 1 7.1.11 "World-writable files/dirs secured" c_7_1_11

# 7.1.12 — files/dirs without an owner or group. Auto-chowning is unsafe (which
# owner?), so this REPORTS only and defers the fix to manual review.
c_7_1_12() {
    local unowned=()
    mapfile -t unowned < <(find / -xdev \( -nouser -o -nogroup \) "${CIS_FIND_EXCLUDES[@]}" 2>/dev/null)
    if (( ${#unowned[@]} == 0 )); then
        return 0
    fi
    STATUS_OVERRIDE=MANUAL
    EXTRA_MSG="${#unowned[@]} unowned file(s)/dir(s) found — assign correct ownership manually (list in $LOG_FILE)"
    printf '7.1.12 unowned: %s\n' "${unowned[@]}" >>"$LOG_FILE"
    return 0
}
run 1 7.1.12 "Files/dirs without a valid owner or group (report only)" c_7_1_12

# -----------------------------------------------------------------------------
# 7.2.x — Local user / group settings
# -----------------------------------------------------------------------------
# 7.2.10 — interactive users' dot files are not group/world writable.
c_7_2_10() {
    if ! bool "$CIS_7_2_10_FIX_USER_DOTFILES"; then
        SKIP_REASON="disabled via CIS_7_2_10_FIX_USER_DOTFILES"
        return 0
    fi
    local homes=() h hits=() total=0 f
    mapfile -t homes < <(awk -F: '($3>=1000 && $3!=65534 && $7!~/(nologin|false)$/){print $6}' /etc/passwd)
    for h in "${homes[@]}"; do
        [[ -d $h ]] || continue
        mapfile -t hits < <(find "$h" -maxdepth 1 -name '.*' -type f -perm /0022 2>/dev/null)
        (( ${#hits[@]} )) || continue
        CHANGED=1
        total=$((total + ${#hits[@]}))
        (( DRY_RUN )) && continue
        for f in "${hits[@]}"; do
            chmod go-w "$f" 2>>"$LOG_FILE" || true
            printf '7.2.10 go-w: %s\n' "$f" >>"$LOG_FILE"
        done
    done
    (( total )) && EXTRA_MSG="$total dotfile(s) had group/other write removed"
    return 0
}
run 1 7.2.10 "Interactive users' dotfiles not group/world writable" c_7_2_10
