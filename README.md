# SSH Handoff Project (Multi-Gateway Support)

This repository provides a robust "Jump Host" or "Bastion" infrastructure using standard OpenSSH features. It allows teams (like `noc` or `sre`) to log in via a shared identity but immediately "handoff" the session to a dynamically created, isolated personal user account.

## 1. How It Works (The Login Flow)



When a user (e.g., **Alice** from the **NOC** team) connects to a server, the following sequence occurs:

1.  **Connection:** Alice initiates an SSH connection to the **Gateway User** (`noc`):
    ```bash
    ssh noc@target-host
    ```
2.  **Authentication (SSHD):**
    * `sshd` checks `/etc/ssh/authorized_keys/noc`.
    * It finds Alice's public key.
    * This key has a forced `command="..."` option attached to it.
3.  **Trigger:** Instead of giving Alice a shell as `noc`, `sshd` executes:
    ```bash
    sudo /usr/local/bin/ssh-handoff.sh alice
    ```
4.  **The Handoff Script (Running as Root):**
    * **Context Discovery:** The script detects it was run by `noc` (via `SUDO_USER`).
    * **Target Calculation:** It combines the gateway (`noc`) and the user (`alice`) to define the target identity: **`noc-alice`**.
    * **Cryptographic Verification:**
        * It reads `SSH_USER_AUTH` (provided by `ExposeAuthInfo`) to get the exact key Alice used.
        * It verifies that *this specific key* is authorized for the user `alice` in the `authorized_keys` file.
    * **JIT Provisioning:** If `noc-alice` does not exist, it is created instantly (in the `noc` group).
    * **Path Injection:** The script adds `/home/noc/bin` to `noc-alice`'s PATH in `.bashrc` so she can access team tools.
    * **Session Switch:** The script executes `su - noc-alice`.
5.  **Result:** Alice gets a shell as `noc-alice` in `/home/noc-alice`.

## 2. Security Implications

### The "Gateway" Model
* **Reduced Attack Surface:** Only the gateway users (`noc`, `sre`) and `root` need to be allowed in `sshd_config` (via `Match User`).
* **Isolation:** Users never get a shell as the shared gateway user. They are sandboxed into their own accounts (`noc-alice`, `sre-eve`).

### Authentication & Authorization
* **Source of Truth:** The `/etc/ssh/authorized_keys/<gateway>` file (managed by Ansible) is the single source of truth.
* **No Password Bypass:** Gateway users are forced to use Public Keys (`PasswordAuthentication no`).
* **Direct Login Blocked:** The auto-created users (`noc-alice`) are explicitly blocked from logging in directly via `DenyUsers noc-*`.

### Risks & Mitigations
* **Trust Chain:** The security relies on the fact that the gateway user (`noc`) cannot modify the `authorized_keys` file. This file is owned by `root` and stored in `/etc/ssh/`, not the user's home directory.
* **Shared Group:** Users in the same gateway (e.g., `noc-alice` and `noc-bob`) share the primary group `noc`.

## 3. Management & Operations

### Adding a User (Onboarding)
1.  Obtain the user's SSH Public Key.
2.  Create a file: `ansible/public_keys/<gateway>/<username>.keys` (e.g., `ansible/public_keys/noc/charlie.keys`).
3.  Run the playbook:
    ```bash
    ansible-playbook ansible/manage_keys.yml
    ```
    * This updates `/etc/ssh/authorized_keys/noc`.
    * Charlie can now log in: `ssh noc@host`.

### Removing a User (Offboarding)
1.  Delete the file: `ansible/public_keys/noc/charlie.keys`.
2.  Run the playbook:
    ```bash
    ansible-playbook ansible/manage_keys.yml
    ```
    * **Key Revocation:** Charlie's key is removed from the auth file.
    * **Cleanup:** The Ansible task "Remove stale users" detects `noc-charlie` has no key and **deletes the user account and home directory**.

### Creating a New Gateway Team
1.  Add the new team name (e.g., `developers`) to the `gateways` list in `manage_keys.yml`.
2.  Create directory `ansible/public_keys/developers/`.
3.  Add keys (e.g., `ansible/public_keys/developers/dave.keys`).
4.  Run the playbook.

## 4. Directory Layout

* **`ansible/manage_keys.yml`**: Main playbook.
* **`ansible/tasks/deploy_gateway.yml`**: Logic to deploy a single gateway.
* **`ansible/public_keys/`**: Directory of keys organized by gateway.
    * `noc/` -> Keys for the NOC team.
    * `sre/` -> Keys for the SRE team.
