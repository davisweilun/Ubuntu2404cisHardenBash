# =============================================================================
# lib/common.sh — shared helpers for the CIS Ubuntu 24.04 hardening script
# =============================================================================
# Sourced by harden.sh. Every helper follows the same contract:
#   * check current state first, change ONLY if needed  -> idempotent
#   * set CHANGED=1 when a change was made (or would be made in dry-run)
#   * never restart services inline — call `notify <handler>` instead
#   * in dry-run mode (DRY_RUN=1) nothing on disk is touched
#
# Control functions may also set:
#   SKIP_REASON      -> control is reported as SKIP with this reason
#   EXTRA_MSG        -> appended to the report line (e.g. "3 files fixed")
#   STATUS_OVERRIDE  -> force a status (e.g. MANUAL for report-only controls)
# =============================================================================

# --- colors (only when stdout is a terminal) ---------------------------------
if [[ -t 1 ]]; then
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; BLU=$'\033[34m'
    MAG=$'\033[35m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
    RED=""; GRN=""; YLW=""; BLU=""; MAG=""; BLD=""; RST=""
fi

# --- counters / result store --------------------------------------------------
N_OK=0; N_FIXED=0; N_SKIP=0; N_FAIL=0; N_MANUAL=0
RESULTS=()
declare -A NOTIFY=()
declare -A BACKED_UP=()

bool() {
    # bool VALUE -> succeeds when VALUE means "true" (true/yes/on/1)
    case "${1:-}" in
        true|True|TRUE|yes|Yes|on|1) return 0 ;;
        *) return 1 ;;
    esac
}

log()  { printf '%s\n' "$*" | tee -a "$LOG_FILE"; }
info() { printf '%b%s%b\n' "$BLD" "$*" "$RST" | tee -a "$LOG_FILE"; }
warn() { printf '%bWARN:%b %s\n' "$YLW" "$RST" "$*" | tee -a "$LOG_FILE"; }

record() {
    # record ID STATUS MESSAGE — one report line per control
    local id=$1 st=$2 msg=$3 color=""
    case $st in
        OK)              color=$GRN; N_OK=$((N_OK + 1)) ;;
        FIXED|WOULD-FIX) color=$YLW; N_FIXED=$((N_FIXED + 1)) ;;
        SKIP)            color=$BLU; N_SKIP=$((N_SKIP + 1)) ;;
        MANUAL)          color=$MAG; N_MANUAL=$((N_MANUAL + 1)) ;;
        FAIL)            color=$RED; N_FAIL=$((N_FAIL + 1)) ;;
    esac
    printf '%b[%-9s]%b CIS %-10s %s\n' "$color" "$st" "$RST" "$id" "$msg" \
        | tee -a "$LOG_FILE"
    RESULTS+=("$st|$id|$msg")
}

notify() {
    # notify HANDLER — queue a service restart/reload, flushed once at the end
    NOTIFY[$1]=1
}

selected() {
    # selected ID — does this control pass the --sections/--control filters?
    local id=$1 sec=${1%%.*}
    if [[ -n $RUN_CONTROL ]]; then
        [[ $id == "$RUN_CONTROL"* || $RUN_CONTROL == "$id"* ]] || return 1
    fi
    if [[ -n $RUN_SECTIONS ]]; then
        [[ ",$RUN_SECTIONS," == *",$sec,"* ]] || return 1
    fi
    return 0
}

run() {
    # run LEVEL ID TITLE FUNCTION [ARGS...]
    # Wraps one control: filtering, L1/L2 gating, status reporting, error
    # isolation (a failing control never aborts the whole run).
    local level=$1 id=$2 title=$3 fn=$4
    shift 4

    selected "$id" || return 0
    if [[ -n $RUN_LEVEL && $RUN_LEVEL != "$level" ]]; then
        return 0
    fi
    if [[ $level == 2 ]] && ! bool "$CIS_LEVEL2_ENABLED"; then
        record "$id" SKIP "$title — Level 2 disabled (CIS_LEVEL2_ENABLED=false)"
        return 0
    fi

    CHANGED=0; SKIP_REASON=""; EXTRA_MSG=""; STATUS_OVERRIDE=""
    if "$fn" "$@"; then
        local msg="$title${EXTRA_MSG:+ — $EXTRA_MSG}"
        if [[ -n $STATUS_OVERRIDE ]]; then
            record "$id" "$STATUS_OVERRIDE" "$msg"
        elif [[ -n $SKIP_REASON ]]; then
            record "$id" SKIP "$title — $SKIP_REASON"
        elif (( CHANGED )); then
            if (( DRY_RUN )); then
                record "$id" WOULD-FIX "$msg"
            else
                record "$id" FIXED "$msg"
            fi
        else
            record "$id" OK "$msg"
        fi
    else
        record "$id" FAIL "$title${EXTRA_MSG:+ — $EXTRA_MSG} (see $LOG_FILE)"
    fi
    return 0
}

# =============================================================================
# File helpers
# =============================================================================

backup_file() {
    # backup_file PATH — copy to the run's backup dir once, preserving the tree
    local f=$1
    [[ -f $f ]] || return 0
    [[ ${BACKED_UP[$f]:-} ]] && return 0
    mkdir -p "$BACKUP_DIR$(dirname "$f")"
    cp -a "$f" "$BACKUP_DIR$f"
    BACKED_UP[$f]=1
}

restore_file() {
    # restore_file PATH — undo this run's change (used after failed validation)
    local f=$1
    if [[ -f "$BACKUP_DIR$f" ]]; then
        cp -a "$BACKUP_DIR$f" "$f"
    else
        rm -f "$f"
    fi
}

ensure_perms() {
    # ensure_perms PATH MODE [OWNER GROUP] — fix mode/ownership if they differ
    local path=$1 mode=$2 owner=${3:-root} group=${4:-root}
    [[ -e $path ]] || return 0
    local cur want
    cur=$(stat -c '%a %U %G' "$path")
    want="$(printf '%o' $((8#$mode))) $owner $group"
    if [[ $cur != "$want" ]]; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            chmod "$mode" "$path"
            chown "$owner:$group" "$path"
        fi
    fi
}

ensure_dir() {
    # ensure_dir PATH [MODE] — create directory if missing, fix perms
    local d=$1 mode=${2:-0755}
    if [[ ! -d $d ]]; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            mkdir -p "$d"
            chmod "$mode" "$d"
            chown root:root "$d"
        fi
    else
        ensure_perms "$d" "$mode"
    fi
}

ensure_file_content() {
    # ensure_file_content DEST MODE [OWNER GROUP]  (desired content on stdin)
    # Full-file management: rewrite only when content differs. Backs up first.
    local dest=$1 mode=${2:-0644} owner=${3:-root} group=${4:-root}
    local content cur=""
    content=$(cat)
    [[ -f $dest ]] && cur=$(<"$dest")
    if [[ $cur != "$content" ]]; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            backup_file "$dest"
            mkdir -p "$(dirname "$dest")"
            printf '%s\n' "$content" > "$dest"
            chmod "$mode" "$dest"
            chown "$owner:$group" "$dest"
            return 0
        fi
    fi
    ensure_perms "$dest" "$mode" "$owner" "$group"
}

ensure_line() {
    # ensure_line FILE REGEX LINE [CREATE_MODE]
    # lineinfile equivalent: replace the first line matching REGEX with LINE
    # (dropping duplicates), or append LINE if no match. Creates FILE if absent.
    local file=$1 regex=$2 line=$3 mode=${4:-0644}
    if [[ ! -f $file ]]; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            printf '%s\n' "$line" > "$file"
            chmod "$mode" "$file"
            chown root:root "$file"
        fi
        return 0
    fi
    local tmp
    tmp=$(mktemp)
    # LINE goes via the environment so awk applies no backslash processing.
    CIS_LINE="$line" awk -v rx="$regex" '
        BEGIN { done = 0; line = ENVIRON["CIS_LINE"] }
        $0 ~ rx { if (!done) { print line; done = 1 }; next }
        { print }
        END { if (!done) print line }' "$file" > "$tmp"
    if ! cmp -s "$file" "$tmp"; then
        CHANGED=1
        if (( ! DRY_RUN )); then
            backup_file "$file"
            cat "$tmp" > "$file"
        fi
    fi
    rm -f "$tmp"
}

_sysctl_norm_key() {
    # normalize "net/ipv4/conf/all/log_martians" or padded keys to dot form
    printf '%s' "$1" | tr -d '[:blank:]' | tr '/' '.'
}

sysctl_has_conflict() {
    # sysctl_has_conflict FILE KEY VAL — true if FILE assigns KEY (exact or
    # glob pattern like net.ipv4.conf.*.rp_filter) a value other than VAL
    local file=$1 key=$2 val=$3 line k v
    [[ -f $file ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == *=* ]] || continue
        [[ $line =~ ^[[:space:]]*[\#\;] ]] && continue
        k=$(_sysctl_norm_key "${line%%=*}")
        v="${line#*=}"; v="${v//[[:blank:]]/}"
        [[ -n $k ]] || continue
        # shellcheck disable=SC2254
        case $key in
            $k) [[ $v != "$val" ]] && return 0 ;;
        esac
    done <"$file"
    return 1
}

sysctl_fix_conflicts_in() {
    # sysctl_fix_conflicts_in FILE KEY VAL — comment out conflicting assignments
    local file=$1 key=$2 val=$3 line k v tmp any=0
    sysctl_has_conflict "$file" "$key" "$val" || return 0
    CHANGED=1
    (( DRY_RUN )) && return 0
    tmp=$(mktemp)
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line == *=* && ! $line =~ ^[[:space:]]*[\#\;] ]]; then
            k=$(_sysctl_norm_key "${line%%=*}")
            v="${line#*=}"; v="${v//[[:blank:]]/}"
            # shellcheck disable=SC2254
            case $key in
                $k)
                    if [[ $v != "$val" ]]; then
                        printf '# commented by CIS hardening — conflicts with %s = %s\n#%s\n' \
                            "$key" "$val" "$line" >>"$tmp"
                        any=1
                        continue
                    fi ;;
            esac
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$file"
    if (( any )); then
        backup_file "$file"
        cat "$tmp" > "$file"
    fi
    rm -f "$tmp"
}

ensure_sysctl() {
    # ensure_sysctl DROPIN_FILE KEY VALUE — persist in /etc/sysctl.d + apply live.
    # Also neutralizes conflicting assignments elsewhere: CIS audits fail a
    # parameter when ANY sysctl source (incl. /etc/ufw/sysctl.conf) holds a
    # different value, even though our drop-in wins at apply time.
    local file=$1 key=$2 val=$3 cur cf mask
    ensure_line "$file" "^${key}[[:space:]]*=" "${key} = ${val}"
    for cf in /etc/sysctl.conf /etc/ufw/sysctl.conf /etc/sysctl.d/*.conf; do
        [[ -f $cf && $cf != "$file" ]] || continue
        sysctl_fix_conflicts_in "$cf" "$key" "$val"
    done
    # /usr/lib/sysctl.d drop-ins are package-owned: mask by copying the file to
    # /etc/sysctl.d (same basename overrides it entirely) and editing the copy.
    for cf in /usr/lib/sysctl.d/*.conf; do
        [[ -f $cf ]] || continue
        mask="/etc/sysctl.d/$(basename "$cf")"
        [[ -f $mask ]] && continue
        if sysctl_has_conflict "$cf" "$key" "$val"; then
            CHANGED=1
            if (( ! DRY_RUN )); then
                cp -a "$cf" "$mask"
                sysctl_fix_conflicts_in "$mask" "$key" "$val"
            fi
        fi
    done
    # Apply to the running kernel only if the key exists (e.g. IPv6 may be off).
    if cur=$(sysctl -n "$key" 2>/dev/null); then
        if [[ $cur != "$val" ]]; then
            CHANGED=1
            if (( ! DRY_RUN )); then
                sysctl -w "${key}=${val}" >/dev/null 2>>"$LOG_FILE" || true
            fi
        fi
    fi
}

blacklist_module() {
    # blacklist_module NAME CONTROL_ID — modprobe.d install-stub + blacklist
    local name=$1 control=$2
    ensure_file_content "/etc/modprobe.d/cis-${name}.conf" 0644 <<EOF
# Managed by CIS hardening — control ${control}
install ${name} /bin/true
blacklist ${name}
EOF
}

ensure_fstab_entry() {
    # ensure_fstab_entry MOUNTPOINT SRC FSTYPE OPTS — fstab line + live remount
    local mp=$1 src=$2 fstype=$3 opts=$4
    ensure_line /etc/fstab \
        "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]" \
        "${src} ${mp} ${fstype} ${opts} 0 0"
    if mountpoint -q "$mp"; then
        local live o
        live=$(findmnt -no OPTIONS "$mp")
        for o in nodev nosuid noexec; do
            if [[ ",$opts," == *",$o,"* && ",$live," != *",$o,"* ]]; then
                CHANGED=1
                if (( ! DRY_RUN )); then
                    mount -o "remount,${opts}" "$mp" 2>>"$LOG_FILE" || return 1
                fi
                break
            fi
        done
    fi
}

# =============================================================================
# Package helpers (apt). Air-gap friendly: if apt cannot install (no mirror
# reachable), the control is reported SKIP rather than aborting the run.
# =============================================================================

pkg_installed() {
    dpkg-query -W -f '${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

APT_REFRESH_OK=0
APT_REFRESH_TRIES=0
apt_refresh() {
    # Refresh the package lists before the run's first install — only when an
    # install is actually needed (a run with nothing to install never touches
    # the network). A failed update is retried once at the next install
    # (transient network hiccup), then abandoned so air-gapped hosts aren't
    # slowed by a network timeout per package; the subsequent install then
    # decides between proceeding from cache and reporting SKIP.
    (( APT_REFRESH_OK )) && return 0
    (( APT_REFRESH_TRIES >= 2 )) && return 0
    APT_REFRESH_TRIES=$((APT_REFRESH_TRIES + 1))
    if DEBIAN_FRONTEND=noninteractive apt update >>"$LOG_FILE" 2>&1; then
        APT_REFRESH_OK=1
    fi
}

pkg_present() {
    # pkg_present NAME... — install missing packages
    local p missing=()
    for p in "$@"; do
        pkg_installed "$p" || missing+=("$p")
    done
    (( ${#missing[@]} )) || return 0
    CHANGED=1
    (( DRY_RUN )) && return 0
    apt_refresh
    if ! DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
            "${missing[@]}" >>"$LOG_FILE" 2>&1; then
        SKIP_REASON="package(s) not installable: ${missing[*]} (no repo/mirror reachable?)"
        CHANGED=0
    fi
}

pkg_absent() {
    # pkg_absent NAME... — purge installed packages
    local p present=()
    for p in "$@"; do
        pkg_installed "$p" && present+=("$p")
    done
    (( ${#present[@]} )) || return 0
    CHANGED=1
    (( DRY_RUN )) && return 0
    DEBIAN_FRONTEND=noninteractive apt purge -y "${present[@]}" \
        >>"$LOG_FILE" 2>&1
}
