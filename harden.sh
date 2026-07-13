#!/usr/bin/env bash
# =============================================================================
# harden.sh — CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 (L1 + L2) hardening
# =============================================================================
# Pure-Bash port of the Ubuntu2404cisHardening Ansible playbook. Runs locally
# on the host being hardened — no Ansible, no Python deps, no network needed.
#
# Usage:
#   sudo ./harden.sh                     # apply all sections (deferred excluded)
#   sudo ./harden.sh --dry-run           # report what WOULD change, touch nothing
#   sudo ./harden.sh --sections 1,2,3    # only these CIS sections
#   sudo ./harden.sh --control 5.1       # a single control (prefix match)
#   sudo ./harden.sh --level 1           # only Level 1 controls
#   sudo ./harden.sh --deferred          # ALSO run disruptive/reboot controls
#
# Idempotent: a second consecutive run should report zero FIXED items.
# Backups of every modified file: /var/backups/cis-hardening/<timestamp>/
# Full log: /var/log/cis-hardening/run-<timestamp>.log
# =============================================================================

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# --- defaults / CLI ----------------------------------------------------------
CONFIG_FILE="$SCRIPT_DIR/config/hardening.conf"
RUN_SECTIONS=""          # empty = all
RUN_CONTROL=""           # empty = all
RUN_LEVEL=""             # empty = both levels
DRY_RUN=0
FORCE_DEFERRED=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)   CONFIG_FILE=$2; shift 2 ;;
        -s|--sections) RUN_SECTIONS=$2; shift 2 ;;
        -k|--control)  RUN_CONTROL=$2; shift 2 ;;
        -l|--level)    RUN_LEVEL=$2; shift 2 ;;
        -n|--dry-run)  DRY_RUN=1; shift ;;
        -d|--deferred) FORCE_DEFERRED=1; shift ;;
        -h|--help)     usage ;;
        *) echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

# --- preflight ---------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo ./harden.sh)." >&2
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found — cannot verify OS." >&2
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
if [[ ${ID:-} != ubuntu ]] || ! dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04; then
    echo "ERROR: this script targets Ubuntu 24.04+. Detected: ${ID:-?} ${VERSION_ID:-?}" >&2
    exit 1
fi

if [[ ! -r $CONFIG_FILE ]]; then
    echo "ERROR: config file not found: $CONFIG_FILE" >&2
    exit 1
fi

# --- init run dirs / logging ---------------------------------------------------
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_DIR=/var/log/cis-hardening
BACKUP_DIR="/var/backups/cis-hardening/$RUN_TS"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/run-$RUN_TS.log"
: > "$LOG_FILE"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=config/hardening.conf
source "$CONFIG_FILE"

(( FORCE_DEFERRED )) && CIS_RUN_DEFERRED=true

info "============================================================"
info " CIS Ubuntu 24.04 v2.0.0 hardening — $(hostname) — $RUN_TS"
info "   mode:     $( ((DRY_RUN)) && echo 'DRY-RUN (no changes)' || echo APPLY )"
info "   level:    ${RUN_LEVEL:-1+2}   sections: ${RUN_SECTIONS:-all}   control: ${RUN_CONTROL:-all}"
info "   deferred: $CIS_RUN_DEFERRED   L2 enabled: $CIS_LEVEL2_ENABLED"
info "   log:      $LOG_FILE"
info "   backups:  $BACKUP_DIR"
info "============================================================"

if bool "$CIS_2_3_MANAGE_TIMESYNCD" && [[ $CIS_2_3_NTP_SERVERS == *example.org* ]]; then
    warn "CIS_2_3_NTP_SERVERS still holds placeholder values — time sync will not work until you set real NTP servers in $CONFIG_FILE"
fi

# --- run sections --------------------------------------------------------------
declare -A SECTION_FILE=(
    [1]="section1_fs.sh"
    [2]="section2_services.sh"
    [3]="section3_network.sh"
    [4]="section4_firewall.sh"
    [5]="section5_access.sh"
    [6]="section6_logging.sh"
    [7]="section7_system.sh"
)
declare -A SECTION_TITLE=(
    [1]="Initial Setup"
    [2]="Services"
    [3]="Network"
    [4]="Host-Based Firewall"
    [5]="Access, Authentication & Authorization"
    [6]="Logging & Auditing"
    [7]="System Maintenance"
)

for s in 1 2 3 4 5 6 7; do
    if [[ -n $RUN_SECTIONS && ",$RUN_SECTIONS," != *",$s,"* ]]; then
        continue
    fi
    info ""
    info "--- Section $s — ${SECTION_TITLE[$s]} ---"
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/sections/${SECTION_FILE[$s]}"
done

if bool "$CIS_RUN_DEFERRED"; then
    info ""
    info "--- Deferred — disruptive / reboot-required controls ---"
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/sections/deferred.sh"
fi

# --- flush handlers (service restarts, queued once, sshd validated + last) -----
flush_handlers() {
    if (( DRY_RUN )); then
        if (( ${#NOTIFY[@]} )); then
            info ""
            info "dry-run: skipping service reloads that a real run would do: ${!NOTIFY[*]}"
        fi
        return 0
    fi
    (( ${#NOTIFY[@]} )) || return 0
    info ""
    info "--- Applying queued service reloads ---"
    if [[ ${NOTIFY[dconf]:-} ]]; then
        log "handler: dconf update"
        dconf update >>"$LOG_FILE" 2>&1 || warn "dconf update failed"
    fi
    if [[ ${NOTIFY[apport]:-} ]]; then
        log "handler: stop + disable apport"
        systemctl stop apport.service >>"$LOG_FILE" 2>&1 || true
        systemctl disable apport.service >>"$LOG_FILE" 2>&1 || true
    fi
    if [[ ${NOTIFY[initramfs]:-} ]]; then
        log "handler: update-initramfs -u"
        update-initramfs -u >>"$LOG_FILE" 2>&1 || warn "update-initramfs failed"
    fi
    if [[ ${NOTIFY[timesyncd]:-} ]]; then
        log "handler: restart systemd-timesyncd"
        systemctl restart systemd-timesyncd >>"$LOG_FILE" 2>&1 \
            || warn "systemd-timesyncd restart failed (chrony in use instead?)"
    fi
    if [[ ${NOTIFY[journald]:-} ]]; then
        log "handler: restart systemd-journald"
        systemctl restart systemd-journald >>"$LOG_FILE" 2>&1 || warn "journald restart failed"
    fi
    if [[ ${NOTIFY[auditd]:-} ]]; then
        log "handler: augenrules --load"
        # Tolerate the non-zero exit when the config is locked immutable (-e 2).
        augenrules --load >>"$LOG_FILE" 2>&1 || warn "augenrules --load returned non-zero (immutable mode?)"
    fi
    if [[ ${NOTIFY[sshd]:-} ]]; then
        # LAST, and only after the full config validates — lockout protection.
        log "handler: validate sshd config, then restart ssh"
        if /usr/sbin/sshd -t >>"$LOG_FILE" 2>&1; then
            systemctl restart ssh >>"$LOG_FILE" 2>&1 || warn "ssh restart failed"
            warn "sshd restarted — OPEN A SECOND SSH SESSION NOW to confirm access before closing this one."
        else
            warn "sshd config validation FAILED — ssh NOT restarted. Inspect $LOG_FILE"
        fi
    fi
}
flush_handlers

# --- summary --------------------------------------------------------------------
info ""
info "============================================================"
info " Summary"
info "============================================================"
log "  OK (already compliant) : $N_OK"
log "  $( ((DRY_RUN)) && echo 'WOULD-FIX             ' || echo 'FIXED                 ' ) : $N_FIXED"
log "  SKIPPED (opt-in/toggle) : $N_SKIP"
log "  MANUAL follow-up        : $N_MANUAL"
log "  FAILED                  : $N_FAIL"
log ""
if (( N_MANUAL > 0 )); then
    log "Manual follow-ups:"
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r st id msg <<<"$r"
        [[ $st == MANUAL ]] && log "  - CIS $id: $msg"
    done
    log ""
fi
if (( N_FAIL > 0 )); then
    log "Failed controls (details in $LOG_FILE):"
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r st id msg <<<"$r"
        [[ $st == FAIL ]] && log "  - CIS $id: $msg"
    done
    log ""
fi
if (( ! DRY_RUN )) && [[ -d $BACKUP_DIR ]]; then
    log "Backups of modified files: $BACKUP_DIR"
fi
log "Full log: $LOG_FILE"
if (( ! DRY_RUN )); then
    log ""
    log "Idempotency check: run this script again — it should report 0 FIXED."
fi

(( N_FAIL == 0 )) || exit 1
exit 0
