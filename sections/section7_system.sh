# =============================================================================
# Section 7 — System Maintenance   (CIS Ubuntu 24.04 v2.0.0)
# =============================================================================
# Sourced by harden.sh. Ported from the Ansible tasks/section7_system.yml.
# =============================================================================

# The shared `find` pruning arguments (CIS_FIND_EXCLUDES) are built once in
# harden.sh from CIS_7_FS_SCAN_EXCLUDES — keeps the recursive sweeps below from
# touching container/k8s storage. [K8S-RISK][CONTAINER-RISK]

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
# 7.2.10 — interactive users' dot files: no group/world write, owned by the
# user, and no .netrc/.forward/.rhosts (those are flagged for manual removal —
# deleting user files automatically is not safe).
c_7_2_10() {
    if ! bool "$CIS_7_2_10_FIX_USER_DOTFILES"; then
        SKIP_REASON="disabled via CIS_7_2_10_FIX_USER_DOTFILES"
        return 0
    fi
    local user home f total=0 risky=()
    while IFS=: read -r user home; do
        [[ -d $home ]] || continue
        while IFS= read -r f; do
            case $(basename "$f") in
                .netrc|.forward|.rhosts)
                    risky+=("$f")
                    continue ;;
            esac
            local st fix=0
            st=$(stat -c '%a %U' "$f")
            (( 8#${st%% *} & 8#0022 )) && fix=1
            [[ ${st##* } != "$user" ]] && fix=1
            if (( fix )); then
                CHANGED=1
                total=$((total + 1))
                if (( ! DRY_RUN )); then
                    chmod go-w "$f" 2>>"$LOG_FILE" || true
                    chown "$user" "$f" 2>>"$LOG_FILE" || true
                    printf '7.2.10 fixed: %s\n' "$f" >>"$LOG_FILE"
                fi
            fi
        done < <(find "$home" -maxdepth 1 -name '.*' -type f 2>/dev/null)
    done < <(awk -F: '($3>=1000 && $3!=65534 && $7!~/(nologin|false)$/){print $1":"$6}' /etc/passwd)
    (( total )) && EXTRA_MSG="$total dotfile(s) fixed (perms/ownership)"
    if (( ${#risky[@]} )); then
        STATUS_OVERRIDE=MANUAL
        EXTRA_MSG="${EXTRA_MSG:+$EXTRA_MSG; }found ${risky[*]} — review and remove manually"
    fi
    return 0
}
run 1 7.2.10 "Interactive users' dotfiles (perms, ownership, .netrc/.forward/.rhosts)" c_7_2_10
