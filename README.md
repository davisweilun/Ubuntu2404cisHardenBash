# Ubuntu 24.04 CIS Hardening — native Bash

Hardens **Ubuntu Server 24.04** to the **CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 (L1 + L2)** using **pure Bash — zero dependencies**. Clone onto the target VM and run. No Ansible, no Python libraries, no control node, no internet required.

Originally a faithful port of the `Ubuntu2404cisHardening` Ansible project (same safe-by-default toggles, same risk flags). **Phase 2** extended it to full benchmark coverage, driven by CIS-CAT Assessor scan evidence from a live lab VM: ~58 additional controls (cron perms, issue/issue.net banners, dccp/rds/sctp/tipc modules, 12 more network sysctls, sshd Banner/LoginGraceTime/MaxStartups, sudo logfile, GRUB audit params, the full 6.2.3 audit ruleset incl. 32-bit arch lines and generated privileged-command rules, AIDE) plus scanner-exactness fixes (APT literal `"0"`, alternate telnet/ftp packages, dynamic MOTD scripts, sysctl conflicts in `/etc/ufw/sysctl.conf` and friends, password aging for existing users, login.defs UMASK).

---

## Quick start

```bash
git clone <this-repo> && cd Ubuntu2404cisHardenBash

# 1. Set real values (NTP servers at minimum) in the config:
vi config/hardening.conf

# 2. See what would change — touches nothing:
sudo ./harden.sh --dry-run

# 3. Apply:
sudo ./harden.sh

# 4. Idempotency check — a second run must report 0 FIXED:
sudo ./harden.sh
```

Requirements: Ubuntu 24.04+, root (`sudo`). That's it — everything used (bash, awk, sed, findmnt, sysctl, systemctl, pam-auth-update) ships with a stock install.

---

## Layout

```
harden.sh                    # entry point — the only file you run
config/hardening.conf        # ALL tunables and on/off switches (edit this)
lib/common.sh                # idempotent helpers, logging, backup, apt wrappers
sections/section1_fs.sh      # 1.x Initial Setup (modules, mounts, AppArmor, banners, GDM)
sections/section2_services.sh# 2.x Services (avahi/cups/clients, timesyncd, cron)
sections/section3_network.sh # 3.x Network (bluetooth, modules, sysctls)
sections/section4_firewall.sh# 4.x ufw — OFF by default [LOCKOUT-RISK]
sections/section5_access.sh  # 5.x sshd, sudo/su, PAM, account policy
sections/section6_logging.sh # 6.x journald, logfile perms, auditd + rules
sections/section7_system.sh  # 7.x world-writable / unowned files, dotfiles
sections/deferred.sh         # reboot-required controls (usb-storage) — gated
files/pam-configs/           # pam-auth-update profiles (AD/SSSD-safe PAM)
```

## Options

```
sudo ./harden.sh [options]
  -n, --dry-run         report what WOULD change; changes nothing
  -s, --sections 1,2,3  run only these CIS sections
  -k, --control 5.1     run a single control (prefix match, e.g. 1.1.1)
  -l, --level 1         run only Level 1 (or 2) controls
  -d, --deferred        ALSO run disruptive/reboot controls (maintenance window!)
  -c, --config FILE     alternate config file
```

Every run writes:
- **Log:** `/var/log/cis-hardening/run-<timestamp>.log`
- **Backups** of every file before modification: `/var/backups/cis-hardening/<timestamp>/` (mirrors the original paths — copy a file back to undo a change)

Per-control output: `OK` (already compliant) / `FIXED` / `WOULD-FIX` (dry-run) / `SKIP` (toggle off, with reason) / `MANUAL` (human follow-up) / `FAIL`. Exit code is non-zero if anything FAILED.

---

## Before you run — set real values

- **`CIS_2_3_NTP_SERVERS`** in [config/hardening.conf](config/hardening.conf) is a placeholder (`ntp1.example.org`) — set your real NTP server(s), or set `CIS_2_3_MANAGE_TIMESYNCD=false` if chrony already handles time. The script warns loudly while the placeholder remains.
- **`CIS_4_SSH_PORT`** — only matters if you enable the firewall (off by default).

## Safe-by-default: what stays OFF unless you opt in

Same posture as the Ansible original — these controls fail a CIS scan **by deliberate choice** until you flip their toggle:

| Control | Toggle | Why it's off |
|---------|--------|--------------|
| 4.1.x ufw firewall | `CIS_4_MANAGE_UFW` | often owned by a 3rd-party product; `[LOCKOUT-RISK]` |
| 4.1.4 deny outgoing | `CIS_4_1_4_OUTGOING_DENY` | breaks DNS/NTP/updates egress |
| 3.3.1.1-3 IPv4 forwarding off | `CIS_3_3_DISABLE_IP_FORWARDING` | Kubernetes/Docker/routers need forwarding=1 |
| 1.1.1.6 overlay module | `CIS_1_1_1_6_OVERLAY_DISABLE` | breaks all container runtimes |
| 1.3.1.3 AppArmor enforce-all | `CIS_1_3_1_3_ENFORCE_PROFILES` | can break container workloads |
| 6.1.2.8/9 rsyslog TLS | `CIS_6_1_MANAGE_RSYSLOG_TLS` | needs remote loghost + CA |
| 6.2.3.29 audit immutable | `CIS_6_2_AUDIT_IMMUTABLE` | locks rules until reboot |
| deferred: 1.1.1.10 usb-storage | `--deferred` / `CIS_RUN_DEFERRED` | reboot required |

Risk flags used throughout: `[K8S-RISK]` `[CONTAINER-RISK]` `[GPU-RISK]` `[AD-RISK]` `[LOCKOUT-RISK]` `[REBOOT-REQUIRED]`.

## Lab-smart first run

The script touches sshd/PAM/sudo, so scope the first run and widen:

```bash
sudo ./harden.sh --sections 1,2,3,7        # low-risk sections first
sudo ./harden.sh --sections 5              # then sshd/sudo/PAM
```

After Section 5: **open a second SSH session and confirm you can log in before closing your current one** — that is the one place a mistake can lock you out. The script validates the sshd config (`sshd -t`) and rolls back the drop-in automatically if validation fails, and only restarts `ssh` after full validation. On AD-joined hosts: **join the domain first, then run this script** — PAM changes go through `pam-auth-update` profiles, which coexist with SSSD's.

## Air-gapped notes

The script itself needs no network. A few controls install packages (`apparmor`, `auditd`, optionally `ufw`, `rsyslog-gnutls`) — if apt has no reachable mirror, those controls report `SKIP (package(s) not installable)` and the run continues. Pre-bake those packages into your image, or point apt at a local mirror, to get them to apply.

## Out of scope (same as the Ansible project)

- Dedicated partitions (1.1.2.\*.1) — provisioning/image-build time.
- Bootloader password (1.4.1) and the other manual-review controls — see the Ansible repo's `docs/manual_review.md`.

## Validation

Tested end-to-end in an `ubuntu:24.04` container (openssh-server/sudo/cron/rsyslog present): full apply exits 0 (68 controls fixed on a fresh system), a second run reports **0 FIXED** (idempotent), dry-run touches nothing, sshd settings verified live via `sshd -T`, sysctl-conflict neutralization verified against a simulated `/etc/ufw/sysctl.conf`, and `pam-auth-update` correctly merges the faillock/pwhistory profiles. Expected residual scan failures after a full run (`--deferred` + reboot) are only the documented opt-in/high-risk toggles, out-of-scope partition controls, the bootloader password, and any `[K8S-RISK]`-excluded container storage paths.

Note: controls 6.2.1.3/6.2.1.4 (GRUB `audit=1`) and 6.2.3.29 (immutable audit config, opt-in) need a reboot to take runtime effect; the AIDE database first build (6.3.2) can take several minutes on large filesystems.
