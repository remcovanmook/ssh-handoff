# SSH Handoff Project (Multi-Gateway Support)

This repository provides a robust "Jump Host" or "Bastion" infrastructure using standard OpenSSH features. It allows teams (like `noc` or `sre`) to log in via a shared identity but immediately "handoff" the session to a dynamically created, isolated personal user account.

## 1. How It Works (The Login Flow)



1.  **Connection:** Alice (NOC team) initiates an SSH connection to the **Gateway User** (`noc`):
    ```bash
    ssh noc@target-host
    ```
2.  **Authentication (SSHD):**
    * `sshd` checks `/etc/ssh/authorized_keys.d/noc` (root-owned).
    * It finds Alice's public key with a forced `command="..."`.
    * It applies restrictions (No Port Forwarding, etc.) defined in the modular config `/etc/ssh/sshd_config.d/gateway-noc.conf`.
3.  **Trigger:** Instead of giving Alice a shell as `noc`, `sshd` executes:
    ```bash
    sudo /usr/local/bin/ssh-handoff.sh alice
    ```
4.  **The Handoff Script (Running as Root):**
    * **Sanity Checks:** Verifies parent process is `sudo`, checks numeric ownership of key files, etc.
    * **Cryptographic Verification:** Reads `SSH_USER_AUTH` to verify the key used is the one authorized for `alice`. It uses a strict regex check (`^command="... $USER" $TYPE $BLOB`) to ensure the key blob matches the authorized command line.
    * **JIT Provisioning:** Creates `noc-alice` if needed.
    * **Shared Environment:** Adds a stub to the new user's `.bashrc` that sources `/etc/ssh-handoff/<gateway>.sh`, but only if that file and its directory are root-owned and not group/other writable. That file prepends the gateway's root-owned `~/bin` to `PATH` and exports any team variables. Shared code and variables live there, never in per-user dotfiles.
    * **Session Switch:** Executes `runuser` (preferred) or `env -i su -` to cleanly switch to `noc-alice`.

## 2. Directory Layout

* **`ansible/manage_keys.yml`**: Main playbook.
* **`ansible/tasks/deploy_gateway.yml`**: Logic to deploy a single gateway.
* **`ansible/templates/gateway_env.sh.j2`**: Shared per-gateway environment (`/etc/ssh-handoff/<gateway>.sh`).
* **`ansible/public_keys/`**: Directory of keys organized by gateway.
    * `noc/` -> Keys for the NOC team.
    * `sre/` -> Keys for the SRE team.

## 3. Security Features

* **Modular Config:** Uses `/etc/ssh/sshd_config.d/` to isolate gateway restrictions.
* **Strict File Permissions:** `authorized_keys` stored in `/etc/ssh/authorized_keys.d/` and owned by `root`.
* **Numeric ID Checks:** Script verifies UID 0 ownership to avoid name spoofing.
* **Path Safety:** Uses `readlink -f` to resolve paths and block symlinks.
* **Audit Logging:** Logs the SHA fingerprint of the key used for access.
* **Regex Verification:** Enforces that the authentication key matches the authorized command structure.

## 4. Usage

1.  **Add Keys:** Create `ansible/public_keys/<gateway>/<user>.keys`.
    * `<user>` must match `^[a-z_][a-z0-9_-]*$`.
    * One key per line as `<type> <blob> [comment]`. Lines with their own SSH options (`from=`, `no-pty`, ...) are rejected; restrictions live in the sshd drop-in instead.
2.  **Team Variables (optional):** Set `gateway_env_vars` in `ansible/manage_keys.yml`, e.g. `{noc: {TEAM: noc}}`. They are exported from `/etc/ssh-handoff/<gateway>.sh` and reach existing users on their next login.
3.  **Run Playbook:** `ansible-playbook ansible/manage_keys.yml`. The sshd config is tested with `sshd -t` before any restart.

## 5. License

Copyright 2025 Remco van Mook

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
