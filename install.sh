#!/bin/bash

set -e

# --- Configuration ---
readonly SCRIPT_PATH="/usr/local/bin/ssh-handoff.sh"
readonly SUDOERS_COMMON="/etc/sudoers.d/00-ssh-handoff-common"
readonly GATEWAY_USER="${1:-noc}"
readonly SUDOERS_USER_FILE="/etc/sudoers.d/99-ssh-handoff-${GATEWAY_USER}"
readonly AUTH_KEYS_DIR="/etc/ssh/authorized_keys.d"
readonly AUTH_KEYS_FILE="$AUTH_KEYS_DIR/$GATEWAY_USER"
readonly ENV_DIR="/etc/ssh-handoff"
readonly ENV_FILE="$ENV_DIR/$GATEWAY_USER.sh"
readonly SSH_CONFIG_FILE="/etc/ssh/sshd_config"
readonly SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly SSH_DROPIN_FILE="$SSH_DROPIN_DIR/gateway-${GATEWAY_USER}.conf"

# --- 1. Root Check ---
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

echo "Starting SSH-Handoff installation for gateway: $GATEWAY_USER"

# --- 2. Create Gateway User ---
if ! id "$GATEWAY_USER" &>/dev/null; then
    echo "Creating user '$GATEWAY_USER'..."
    # Valid shell required for forced command to execute
    useradd -m -s /bin/bash "$GATEWAY_USER"
    
    # Set invalid password (*) to prevent password login
    # But DO NOT use usermod -L (lock) as it triggers PAM denials on some systems
    usermod -p '*' "$GATEWAY_USER"
else
    echo "User '$GATEWAY_USER' already exists."
fi

# --- 3. Create System Authorized Keys Directory ---
echo "Creating directory $AUTH_KEYS_DIR..."
mkdir -p "$AUTH_KEYS_DIR"
chown root:root "$AUTH_KEYS_DIR"
chmod 755 "$AUTH_KEYS_DIR"

echo "Creating/Securing $AUTH_KEYS_FILE..."
touch "$AUTH_KEYS_FILE"
chown root:root "$AUTH_KEYS_FILE"
chmod 644 "$AUTH_KEYS_FILE"

# --- 3b. Shared Environment File ---
# Sourced from each $GATEWAY_USER-* user's .bashrc. Left alone if it already
# exists so local additions (team variables etc.) survive a re-run.
echo "Creating directory $ENV_DIR..."
mkdir -p "$ENV_DIR"
chown root:root "$ENV_DIR"
chmod 755 "$ENV_DIR"

if [ ! -f "$ENV_FILE" ]; then
    echo "Creating shared environment file $ENV_FILE..."
    GATEWAY_HOME=$(getent passwd "$GATEWAY_USER" | cut -d: -f6)
    {
        echo "#"
        echo "# Shared environment for Gateway: $GATEWAY_USER"
        echo "# Sourced from the .bashrc of every $GATEWAY_USER-* user."
        echo "# Add team-wide variables at the bottom (export NAME=value)."
        echo "#"
        echo ""
        echo "# Team tools: prepend the gateway's bin dir to PATH, but only if it is a real"
        echo "# directory owned by root and not writable by group or other."
        echo "_tt_dir=\"$GATEWAY_HOME/bin\""
        cat <<'ENV_CONTENT'
if [ -d "$_tt_dir" ] && [ ! -L "$_tt_dir" ] \
    && read -r _tt_uid _tt_mode < <(stat -c '%u %a' -- "$_tt_dir" 2>/dev/null) \
    && [ "$_tt_uid" = 0 ] && [[ "$_tt_mode" =~ ^[0-7]+$ ]] \
    && (( (8#$_tt_mode & 022) == 0 )); then
    case ":$PATH:" in
        *:"$_tt_dir":*) ;;
        *) PATH="$_tt_dir:$PATH" ;;
    esac
fi
unset _tt_dir _tt_uid _tt_mode
ENV_CONTENT
    } > "$ENV_FILE"
else
    echo "Shared environment file $ENV_FILE already exists, leaving it alone."
fi
chown root:root "$ENV_FILE"
chmod 644 "$ENV_FILE"

# --- 4. Create the Handoff Script ---
echo "Creating handoff script at $SCRIPT_PATH..."
# Same content as ansible/files/ssh-handoff.sh
cat <<'SCRIPT_CONTENT' > "$SCRIPT_PATH"
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
# Per-gateway shared environment (<gateway>.sh), root-owned
readonly ENV_DIR="/etc/ssh-handoff"

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

# Escape all ERE metacharacters so type and blob match literally
# (base64 has '+' and '/', key types like sk-ssh-ed25519@openssh.com have '.')
ESCAPED_TYPE=$(printf '%s\n' "$AUTH_KEY_TYPE" | sed 's/[][\.*^$+?(){}|]/\\&/g')
ESCAPED_BLOB=$(printf '%s\n' "$AUTH_KEY_BLOB" | sed 's/[][\.*^$+?(){}|]/\\&/g')

# Construct Strict Regex
# Expects: command="... ssh-handoff.sh <user>" <type> <blob>[ <comment>]
# The blob is anchored at both ends so a prefix of a longer blob cannot match.
MATCH_PATTERN="^command=\"[^\"]*ssh-handoff\.sh $REQUESTED_USER\" $ESCAPED_TYPE $ESCAPED_BLOB( |\$)"

# Verify against file
if ! grep -qE "$MATCH_PATTERN" "$AUTHORIZED_KEYS_FILE"; then
    log_and_exit "Security Mismatch: Key used is not authorized for user '$REQUESTED_USER'."
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
        # --- Shared Environment Hook ---
        # .bashrc only gets a stub that sources ${ENV_DIR}/<gateway>.sh.
        # Shared code and variables live in that root-owned file, so changes
        # reach existing users without rewriting their .bashrc.
        TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
        BASH_RC="$TARGET_HOME/.bashrc"

        if [ -d "$TARGET_HOME" ]; then
            # create if missing
            if [ ! -f "$BASH_RC" ]; then
                install -m 0600 -o "$TARGET_USER" -g "$GATEWAY_USER" /dev/null "$BASH_RC"
            fi

            # refuse to modify if it is a symlink
            if [ -L "$BASH_RC" ]; then
                logger -t ssh-handoff "WARN: .bashrc for $TARGET_USER is a symlink - skipping environment hook"
            elif ! grep -Fq "Shared team environment (added by ssh-handoff)" "$BASH_RC"; then
                {
                    echo ""
                    echo "# Shared team environment (added by ssh-handoff)"
                    echo "SSH_HANDOFF_ENV=\"$ENV_DIR/$GATEWAY_USER.sh\""
                    # Source only if the file and its directory are root-owned
                    # and not writable by group or other.
                    cat <<'BASHRC'
_ssh_handoff_trusted() {
    local uid mode
    read -r uid mode < <(stat -c '%u %a' -- "$1" 2>/dev/null) || return 1
    [ "$uid" = 0 ] && [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 022) == 0 ))
}
if [ -f "$SSH_HANDOFF_ENV" ] && [ ! -L "$SSH_HANDOFF_ENV" ] \
    && _ssh_handoff_trusted "${SSH_HANDOFF_ENV%/*}" \
    && _ssh_handoff_trusted "$SSH_HANDOFF_ENV"; then
    . "$SSH_HANDOFF_ENV"
fi
unset -f _ssh_handoff_trusted
unset SSH_HANDOFF_ENV
BASHRC
                } >> "$BASH_RC"

                chown "$TARGET_USER:$GATEWAY_USER" "$BASH_RC"
                chmod 0600 "$BASH_RC"
                logger -t ssh-handoff "Injected shared environment hook into $BASH_RC"
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
SCRIPT_CONTENT

chown root:root "$SCRIPT_PATH"
chmod 700 "$SCRIPT_PATH"

# --- 5. Create 'sudoers' Files ---
echo "Configuring sudoers..."

# Global Defaults
cat <<SUDO_COMMON > "$SUDOERS_COMMON"
# Global Defaults for SSH Handoff
Defaults env_keep += "SSH_USER_AUTH"
SUDO_COMMON
chmod 440 "$SUDOERS_COMMON"

# Per-Gateway Access
cat <<SUDO_USER > "$SUDOERS_USER_FILE"
# Sudo access for gateway: $GATEWAY_USER
$GATEWAY_USER    ALL=(root)    NOPASSWD: $SCRIPT_PATH
SUDO_USER
chmod 440 "$SUDOERS_USER_FILE"

echo "Sudoers rules created."

# --- 6. Configure SSHD (Modular) ---
echo "Configuring SSHD..."

# Ensure Drop-in Directory Exists
mkdir -p "$SSH_DROPIN_DIR"

# Ensure Include directive is present in main config
if ! grep -q "^Include $SSH_DROPIN_DIR/\*.conf" "$SSH_CONFIG_FILE"; then
    # Add Include at the very top
    sed -i "1i Include $SSH_DROPIN_DIR/*.conf" "$SSH_CONFIG_FILE"
    echo "Added Include directive to $SSH_CONFIG_FILE"
fi

# Enable Global Settings
sed -i -E 's/^[ \t]*#[ \t]*(PubkeyAuthentication).*/\1 yes/g' "$SSH_CONFIG_FILE"
sed -i -E 's/^[ \t]*(PubkeyAuthentication).*/\1 yes/g' "$SSH_CONFIG_FILE"

if ! grep -q "^[ \t]*ExposeAuthInfo" "$SSH_CONFIG_FILE"; then
    echo "ExposeAuthInfo yes" >> "$SSH_CONFIG_FILE"
else
    sed -i -E 's/^[ \t]*#[ \t]*(ExposeAuthInfo).*/\1 yes/g' "$SSH_CONFIG_FILE"
    sed -i -E 's/^[ \t]*(ExposeAuthInfo).*/\1 yes/g' "$SSH_CONFIG_FILE"
fi

# Create Drop-in Config for Gateway
cat <<SSHD_DROPIN > "$SSH_DROPIN_FILE"
# SSH Handoff Config for Gateway: $GATEWAY_USER
# Created by install.sh

DenyUsers ${GATEWAY_USER}-*

Match User $GATEWAY_USER
    PasswordAuthentication no
    AuthorizedKeysFile $AUTH_KEYS_DIR/%u
    AllowTcpForwarding no
    X11Forwarding no
    AllowAgentForwarding no
SSHD_DROPIN

chmod 644 "$SSH_DROPIN_FILE"
echo "Created drop-in config: $SSH_DROPIN_FILE"

# --- 7. Restart SSHD ---
# Never restart on a broken config: that can lock everyone out.
if ! /usr/sbin/sshd -t; then
    echo "sshd config test failed; NOT restarting sshd. Fix the errors above and restart manually." >&2
    exit 1
fi

echo "Restarting SSH service..."
# Debian/Ubuntu name the unit 'ssh', most other distros 'sshd'
if command -v systemctl &> /dev/null; then
    if systemctl cat ssh.service &> /dev/null; then
        systemctl restart ssh
    else
        systemctl restart sshd
    fi
else
    service ssh restart 2>/dev/null || service sshd restart
fi

echo "SSH-Handoff Installation Complete!"
