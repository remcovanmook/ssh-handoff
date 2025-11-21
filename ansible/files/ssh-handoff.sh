#!/bin/bash
#
# THIS FILE IS MANAGED BY ANSIBLE
# HARDENED VERSION + AUDIT LOGGING + PATH INJECTION
#

# === Configuration ===
readonly MIN_ID=2000
readonly MAX_ID=5000
readonly EXPECTED_OWNER="root"
readonly MAX_USERNAME_LEN=32
readonly AUTH_KEYS_DIR="/etc/ssh/authorized_keys"

# === Arguments ===
readonly REQUESTED_USER="$1"

# === Helper Functions ===
log_and_exit() {
    logger -t ssh-handoff "DENIED: $1"
    echo "Access Denied: $1" >&2
    exit 1
}

get_key_fingerprint() {
    if [ -n "$SSH_USER_AUTH" ] && [ -r "$SSH_USER_AUTH" ]; then
        local key_blob=$(awk '/^publickey/ {print $2}' "$SSH_USER_AUTH")
        if [ -n "$key_blob" ]; then
            echo "$key_blob" | base64 -d 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'
        fi
    fi
}

# === 1. Context & Sanity Checks ===
if [ "$(id -u)" -ne 0 ]; then log_and_exit "Script must be run as root."; fi

# Process Check
if [ -r "/proc/$PPID/comm" ]; then PARENT_CMD=$(cat "/proc/$PPID/comm"); else PARENT_CMD=$(ps -p "$PPID" -o comm=); fi
PARENT_CMD=${PARENT_CMD%%[[:space:]]*}
if [ "$PARENT_CMD" != "sudo" ]; then log_and_exit "Execution Integrity Violation: Parent process is '$PARENT_CMD', expected 'sudo'."; fi

# Validate Gateway User
readonly GATEWAY_USER="$SUDO_USER"
if [ -z "$GATEWAY_USER" ]; then log_and_exit "SUDO_USER variable is missing."; fi

# Get Gateway Home (Required for PATH injection)
GATEWAY_HOME=$(getent passwd "$GATEWAY_USER" | cut -d: -f6)

# Determine Target
readonly TARGET_USER="${GATEWAY_USER}-${REQUESTED_USER}"
readonly AUTHORIZED_KEYS_FILE="${AUTH_KEYS_DIR}/${GATEWAY_USER}"

# Secure File Check
if [ ! -f "$AUTHORIZED_KEYS_FILE" ]; then log_and_exit "Authorized keys file missing: $AUTHORIZED_KEYS_FILE"; fi
FILE_STATS=$(stat -c '%U %a' "$AUTHORIZED_KEYS_FILE")
read -r FILE_OWNER FILE_PERMS <<< "$FILE_STATS"
if [ "$FILE_OWNER" != "$EXPECTED_OWNER" ]; then log_and_exit "Security Violation: authorized_keys owned by $FILE_OWNER."; fi
if [[ "$FILE_PERMS" =~ .[2367]. ]] || [[ "$FILE_PERMS" =~ ..[2367] ]]; then log_and_exit "Security Violation: authorized_keys has unsafe permissions."; fi

# === 2. Input Sanitization ===
if ! [[ "$REQUESTED_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then log_and_exit "Invalid requested username format."; fi
if [ "${#TARGET_USER}" -gt "$MAX_USERNAME_LEN" ]; then log_and_exit "Target username exceeds length limit."; fi
if [ "$REQUESTED_USER" = "root" ] || [ "$TARGET_USER" = "root" ] || [ "$TARGET_USER" = "$GATEWAY_USER" ]; then log_and_exit "Forbidden target user."; fi

# === 3. Strong Key Verification ===
if [ -z "$SSH_USER_AUTH" ] || [ ! -r "$SSH_USER_AUTH" ]; then log_and_exit "SSH_USER_AUTH missing/unreadable."; fi
AUTH_KEY_TYPE=$(awk '/^publickey/ { print $2; exit }' "$SSH_USER_AUTH")
AUTH_KEY_BLOB=$(awk '/^publickey/ { print $3; exit }' "$SSH_USER_AUTH")
if [ -z "$AUTH_KEY_BLOB" ]; then log_and_exit "Could not extract authentication key blob."; fi

EXPECTED_CMD="ssh-handoff.sh $REQUESTED_USER"
if ! grep -F "$AUTH_KEY_BLOB" "$AUTHORIZED_KEYS_FILE" | grep -F -q "$EXPECTED_CMD"; then
    log_and_exit "Security Mismatch: Key used is not authorized for user '$REQUESTED_USER'.";
fi

FINGERPRINT=$(echo "$AUTH_KEY_TYPE $AUTH_KEY_BLOB" | ssh-keygen -l -f - 2>/dev/null | awk '{print $2}')
if [ -z "$FINGERPRINT" ]; then FINGERPRINT="unknown"; fi

# === 4. User Provisioning ===
if ! id "$TARGET_USER" &>/dev/null; then
    logger -t ssh-handoff "Provisioning new user: $TARGET_USER in group $GATEWAY_USER"
    
    if ! useradd -m -s /bin/bash -g "$GATEWAY_USER" -K UID_MIN="$MIN_ID" -K UID_MAX="$MAX_ID" "$TARGET_USER" 2>/dev/null; then
        # Useradd failed. Check if it's because of a race condition (created by another thread).
        if ! id "$TARGET_USER" &>/dev/null; then 
            log_and_exit "Failed to create user $TARGET_USER."
        fi
    else
        # User creation SUCCESS by THIS process.
        # Inject the Gateway BIN path into the new user's .bashrc
        TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
        BASH_RC="$TARGET_HOME/.bashrc"
        
        if [ -d "$TARGET_HOME" ]; then
            # Ensure .bashrc exists (useradd -m usually creates it from skel)
            touch "$BASH_RC"
            
            echo "" >> "$BASH_RC"
            echo "# Added by ssh-handoff: Add gateway tools to path" >> "$BASH_RC"
            echo "export PATH=\"\$PATH:$GATEWAY_HOME/bin\"" >> "$BASH_RC"
            
            # Ensure ownership is correct (we are root, file must belong to user)
            chown "$TARGET_USER:$GATEWAY_USER" "$BASH_RC"
            logger -t ssh-handoff "Added $GATEWAY_HOME/bin to $TARGET_USER path."
        fi
    fi
fi

# === 5. Handoff ===
logger -t ssh-handoff "APPROVED: Session for $TARGET_USER [Key: $FINGERPRINT]"
exec /bin/su - "$TARGET_USER"
