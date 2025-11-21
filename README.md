# SSH Handoff Project (Multi-Gateway Support)

This repository provides a robust "Jump Host" or "Bastion" infrastructure using standard OpenSSH features. It allows teams (like `noc` or `sre`) to log in via a shared identity but immediately "handoff" the session to a dynamically created, isolated personal user account.

## 1. How It Works (The Login Flow)



1.  **Connection:** Alice (NOC team) initiates an SSH connection to the **Gateway User** (`noc`):
    ```bash
    ssh noc@target-host
    ```
2.  **Authentication (SSHD):**
    * `sshd` checks `/etc/ssh/authorized_keys/noc` (root-owned).
    * It finds Alice's public key with a forced `command="..."`.
3.  **Trigger:** Instead of giving Alice a shell as `noc`, `sshd` executes:
    ```bash
    sudo /usr/local/bin/ssh-handoff.sh alice
    ```
4.  **The Handoff Script (Running as Root):**
    * **Sanity Checks:** Verifies parent process is `sudo`, checks numeric ownership of key files, etc.
    * **Cryptographic Verification:** Reads `SSH_USER_AUTH` to verify the key used is the one authorized for `alice`.
    * **JIT Provisioning:** Creates `noc-alice` if needed.
    * **Path Injection:** Safely injects `~/bin` from the gateway into the new user's `.bashrc` if owned by root.
    * **Session Switch:** Executes `runuser` (preferred) or `env -i su -` to cleanly switch to `noc-alice`.

## 2. Directory Layout

* **`ansible/manage_keys.yml`**: Main playbook.
* **`ansible/tasks/deploy_gateway.yml`**: Logic to deploy a single gateway.
* **`ansible/public_keys/`**: Directory of keys organized by gateway.
    * `noc/` -> Keys for the NOC team.
    * `sre/` -> Keys for the SRE team.

## 3. Security Features

* **Strict File Permissions:** `authorized_keys` stored in `/etc/ssh/` and owned by `root`.
* **Numeric ID Checks:** Script verifies UID 0 ownership to avoid name spoofing.
* **Path Safety:** Uses `readlink -f` to resolve paths and block symlinks.
* **Audit Logging:** Logs the SHA fingerprint of the key used for access.
* **Regex Verification:** Enforces that the authentication key matches the authorized command structure.

## 4. Usage

1.  **Add Keys:** Create `ansible/public_keys/<gateway>/<user>.keys`.
2.  **Run Playbook:** `ansible-playbook ansible/manage_keys.yml`.
