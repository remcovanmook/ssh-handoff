#!/bin/bash
#
# THIS FILE IS MANAGED BY ANSIBLE
# HARDENED VERSION: Strict Mode, Regex Verification, Clean Handoff
#

set -euo pipefail
umask 0077
PATH='/usr/sbin:/usr/bin:/sbin:/bin'

# === Configuration ===
readonly MIN_ID=2000
readonly MAX_ID=5000
readonly EXPECTED_OWNER_UID=0
readonly MAX_USERNAME_LEN=32
readonly AUTH_KEYS_DIR="/etc/ssh/authorized_keys.d"

# === Arguments ===
# $1 is the requested user (e.g. "alice")
REQUESTED_USER="${1:-}"

# === Helper Functions ===
log_and_exit() {
    logger -t ssh-handoff "DENIED: $1"
    echo "Access Denied: $1" >&2
    exit 1
}

get_key_fingerprint() {
    if [ -n "${SSH_USER_AUTH:-}" ] && [ -r "$SSH_USER_AUTH" ]; then
        local key_blob=$(awk '/^publickey/ {print $3}' "$SSH_USER_AUTH")
        local key_type=$(awk '/^publickey/ {print $2}' "$SSH_USER_AUTH")
        if [ -n "$key_blob" ]; then
            echo "$key_type $key_blob" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'
        fi
    fi
}

# === 1. Context & Sanity Checks ===

# Root Check
if [ "$(id -u)" -ne 0 ]; then
    log_and_exit "Script must be run as root."
fi

# Input Check
if [ -z "$REQUESTED_USER" ]; then
    log_and_exit "missing username"
fi

# Process Origin Check
if [ -r "/proc/$PPID/comm" ]; then
    PARENT_CMD=$(cat "/proc/$PPID/comm")
else
    PARENT_CMD=$(ps -p "$PPID" -o comm=)
fi
PARENT_CMD=${PARENT_CMD%%[[:space:]]*}

if [ "$PARENT_CMD" != "sudo" ]; then
    log_and_exit "Execution Integrity Violation: Parent process is '$PARENT_CMD', expected 'sudo'."
fi

# Validate Gateway User
GATEWAY_USER="${SUDO_USER:-}"
if [ -z "$GATEWAY_USER" ]; then
    log_and_exit "SUDO_USER variable is missing."
fi

# Canonicalize SSH_USER_AUTH if present
if [ -n "${SSH_USER_AUTH:-}" ]; then
    SSH_USER_AUTH="$(readlink -f -- "$SSH_USER_AUTH" 2>/dev/null || true)"
    if [ -z "$SSH_USER_AUTH" ] || [ ! -r "$SSH_USER_AUTH" ]; then
        log_and_exit "SSH_USER_AUTH missing/unreadable"
    fi
fi

# Safe authorized_keys resolution
AUTHORIZED_KEYS_FILE="$(readlink -f -- "${AUTH_KEYS_DIR}/${GATEWAY_USER}" 2>/dev/null || true)"

# Existence check
if [ -z "$AUTHORIZED_KEYS_FILE" ] || [ ! -f "$AUTHORIZED_KEYS_FILE" ]; then
    log_and_exit "missing authorized_keys for $GATEWAY_USER"
fi

# Symlink check
if [ -L "$AUTHORIZED_KEYS_FILE" ]; then
    log_and_exit "authorized_keys is symlink"
fi

# Numeric ownership and mode checks
read -r file_uid file_mode < <(stat -Lc '%u %a' -- "$AUTHORIZED_KEYS_FILE")

if [ "$file_uid" -ne "$EXPECTED_OWNER_UID" ]; then
    log_and_exit "authorized_keys wrong owner uid=$file_uid"
fi

# Permission Check: Ensure Group/Other do not have write (022 mask)
if [ "$(( 8#$file_mode & 022 ))" -ne 0 ]; then
    log_and_exit "authorized_keys too permissive mode=$file_mode"
fi

# === 2. Logic Setup ===

TARGET_USER="${GATEWAY_USER}-${REQUESTED_USER}"

# Input Sanitization
if ! [[ "$REQUESTED_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then log_and_exit "Invalid requested username format."; fi
if [ "${#TARGET_USER}" -gt "$MAX_USERNAME_LEN" ]; then log_and_exit "Target username exceeds length limit."; fi
if [ "$REQUESTED_USER" = "root" ] || [ "$TARGET_USER" = "root" ] || [ "$TARGET_USER" = "$GATEWAY_USER" ]; then log_and_exit "Forbidden target user."; fi

# === 3. Strong Key Verification (Regex) ===

if [ -z "${SSH_USER_AUTH:-}" ]; then
    log_and_exit "SSH_USER_AUTH required for verification."
fi

# Extract Key Data from auth info file
AUTH_KEY_TYPE=$(awk '/^publickey/ { print $2; exit }' "$SSH_USER_AUTH")
AUTH_KEY_BLOB=$(awk '/^publickey/ { print $3; exit }' "$SSH_USER_AUTH")

if [ -z "$AUTH_KEY_BLOB" ]; then
   log_and_exit "Could not extract authentication key blob."
fi

# Escape '+' in the base64 blob for regex safety
ESCAPED_BLOB=$(printf '%s\n' "$AUTH_KEY_BLOB" | sed 's/+/\\+/g')

# Construct Strict Regex
MATCH_PATTERN="^command=\".*ssh-handoff\.sh $REQUESTED_USER\",.* $AUTH_KEY_TYPE $ESCAPED_BLOB"

# Verify against file
if ! grep -qE "$MATCH_PATTERN" "$AUTHORIZED_KEYS_FILE"; then
    log_and_exit "Security Mismatch: Key used is not authorized for user '$REQUESTED_USER' with correct options."
fi

# Calculate fingerprint for logging
FINGERPRINT=$(echo "$AUTH_KEY_TYPE $AUTH_KEY_BLOB" | ssh-keygen -l -f - 2>/dev/null | awk '{print $2}')
if [ -z "$FINGERPRINT" ]; then FINGERPRINT="unknown"; fi

# === 4. User Provisioning ===

if ! id "$TARGET_USER" &>/dev/null; then
    logger -t ssh-handoff "Provisioning new user: $TARGET_USER in group $GATEWAY_USER"

    if ! useradd -m -s /bin/bash \
        -g "$GATEWAY_USER" \
        -K UID_MIN="$MIN_ID" \
        -K UID_MAX="$MAX_ID" \
        "$TARGET_USER" 2>/dev/null; then
        
        # Handle Race Condition
        if ! id "$TARGET_USER" &>/dev/null; then
             log_and_exit "Failed to create user $TARGET_USER."
        fi
    else
        # --- PATH Injection ---
        TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
        GATEWAY_HOME=$(getent passwd "$GATEWAY_USER" | cut -d: -f6)
        BASH_RC="$TARGET_HOME/.bashrc"
        
        if [ -d "$TARGET_HOME" ] && [ -n "$GATEWAY_HOME" ]; then
            # create if missing
            if [ ! -f "$BASH_RC" ]; then
                install -m 0600 -o "$TARGET_USER" -g "$TARGET_USER" /dev/null "$BASH_RC"
            fi

            # refuse to modify if it is a symlink or unsafe
            if [ -L "$BASH_RC" ]; then
                logger -t ssh-handoff "WARN: .bashrc for $TARGET_USER is a symlink - skipping PATH injection"
            else
                # Idempotency check
                if ! grep -Fq "Shared team tools (added by ssh-handoff)" "$BASH_RC"; then
                    {
                        echo ""
                        echo "# Shared team tools (added by ssh-handoff)"
                        # We inject the gateway home path
                        echo "TEAMTOOLS_DIR=\"$GATEWAY_HOME/bin\""
                        echo "if [ -d \"\$TEAMTOOLS_DIR\" ]; then"
                        echo "    TT_UID=\$(stat -f \"%u\" \"\$TEAMTOOLS_DIR\" 2>/dev/null || stat -c \"%u\" \"\$TEAMTOOLS_DIR\" 2>/dev/null)"
                        echo "    TT_MODE=\$(stat -f \"%Lp\" \"\$TEAMTOOLS_DIR\" 2>/dev/null || stat -c \"%a\" \"\$TEAMTOOLS_DIR\" 2>/dev/null)"
                        echo "    case \"\$TT_MODE\" in"
                        echo "        *[2367]) TT_PERM_BAD=true ;;"
                        echo "        *) TT_PERM_BAD=false ;;"
                        echo "    esac"
                        echo "    if [ \"\$TT_UID\" = \"0\" ] && [ \"\$TT_PERM_BAD\" = false ]; then"
                        echo "        case \":\$PATH:\" in"
                        echo "            *:\$TEAMTOOLS_DIR:*) ;;"
                        echo "            *) PATH=\"\$TEAMTOOLS_DIR:\$PATH\" ;;"
                        echo "        esac"
                        echo "    fi"
                        echo "fi"
                    } >> "$BASH_RC"

                    # Ensure permissions are correct
                    chown "$TARGET_USER:$GATEWAY_USER" "$BASH_RC"
                    chmod 0600 "$BASH_RC"
                    logger -t ssh-handoff "Injected secure PATH check into $BASH_RC"
                fi
            fi
        fi
    fi
fi

# === 5. Handoff ===

logger -t ssh-handoff "APPROVED: Session for $TARGET_USER [Key: $FINGERPRINT]"

# Unset sensitive variables before handoff to prevent leakage
unset SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND SSH_USER_AUTH SSH_ORIGINAL_COMMAND

# Try runuser first (modern, cleaner for root->user)
if command -v runuser >/dev/null 2>&1; then
    exec runuser -l "$TARGET_USER"
else
    # Fallback to su, using env -i to scrub environment
    exec env -i TERM="${TERM:-}" su - "$TARGET_USER"
fi
