# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
#
# pathguard.sh — Shell-side write-path policy for Fan Get Fame Fast.
#
# Mirrors lib/path_guard.py for the analyze scripts: evidence, /mnt and /media
# are read-only. Source this file, then call the helpers.
#
#   source "$SCRIPT_DIR/pathguard.sh"
#   fgff_assert_ro_mount "$FS_MOUNT"      # abort unless the mount is read-only
#   fgff_assert_writable "$OUTPUT_DIR"    # abort if path is under a read-only root
#
# These functions call `exit 1` on violation, so they abort the sourcing script
# (the analyze pipelines run with `set -e`).

# Read-only roots. EVIDENCE_ROOT (used by the MCP servers) is honoured when set.
_FGFF_READONLY_ROOTS=(/mnt /media /home/vscode/evidence /home/sansforensics/evidence)
if [[ -n "${EVIDENCE_ROOT:-}" ]]; then
    _FGFF_READONLY_ROOTS+=("$EVIDENCE_ROOT")
fi

# fgff_assert_writable <path>
# Abort if <path> resolves under a read-only root.
fgff_assert_writable() {
    local target
    # Resolve without requiring the path to exist (-m).
    target="$(readlink -m -- "$1")"
    local ro
    for ro in "${_FGFF_READONLY_ROOTS[@]}"; do
        ro="$(readlink -m -- "$ro")"
        if [[ "$target" == "$ro" || "$target" == "$ro"/* ]]; then
            echo "[pathguard] FATAL: refusing to write to read-only location: $target" >&2
            echo "[pathguard]        (under protected root $ro — evidence/mnt/media are read-only)" >&2
            exit 1
        fi
    done
}

# fgff_assert_ro_mount <mountpoint>
# Abort if <mountpoint> is mounted read-write (or is not a mount point at all).
fgff_assert_ro_mount() {
    local mp="$1" opts
    if ! findmnt -rn -o TARGET -- "$mp" >/dev/null 2>&1; then
        echo "[pathguard] FATAL: $mp is not a mount point — refusing to proceed." >&2
        exit 1
    fi
    opts="$(findmnt -rn -o OPTIONS -- "$mp" 2>/dev/null)"
    case ",$opts," in
        *,ro,*) : ;;  # explicitly read-only — good
        *)
            echo "[pathguard] FATAL: $mp is not mounted read-only (options: $opts)." >&2
            echo "[pathguard]        Evidence mounts must be read-only. Aborting." >&2
            exit 1
            ;;
    esac
}
