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
3.  **Trigger:** Instead of giving Alice a shell as `noc`, `sshd` executes:
    ```bash
    sudo /usr/local/bin/ssh-handoff.sh alice
    ```
4.  **The Handoff Script (Running as Root):**
    * **Sanity Checks:** Verifies parent process is `sudo`, checks numeric ownership of key files, etc.
    * **Cryptographic Verification:** Reads `SSH_USER_AUTH` to verify the key used is the one authorized for `alice`. It uses a strict regex check (`^command="... $USER",.* $TYPE $BLOB`) to ensure the key blob matches the authorized command line.
    * **JIT Provisioning:** Creates `noc-alice` if needed.
    * **Path Injection:** Safely injects `~/bin` from the gateway into the new user's `.bashrc` if owned by root.
    * **Session Switch:** Executes `runuser` (preferred) or `env -i su -` to cleanly switch to `noc-alice`.

## 2. Implementation Options

You can implement this system using one of two methods depending on your scale.

### Option 1: Manual Installation (Single Host)
Use this for quick testing or managing a single bastion host without Ansible.

1.  **Run the Installer:**
    ```bash
    # Edits sshd_config, creates 'noc' user, installs handoff script
    sudo ./install.sh
    ```
    *By default, this sets up the 'noc' gateway user.*

2.  **Add Users:**
    You must manually create the key file.
    ```bash
    # Create the file if it doesn't exist
    sudo touch /etc/ssh/authorized_keys.d/noc
    
    # Add a user line (Format MUST be exact):
    # command="sudo /usr/local/bin/ssh-handoff.sh <username>",<options> <key-type> <key-blob> <comment>
    echo 'command="sudo /usr/local/bin/ssh-handoff.sh alice",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-rsa AAAA... alice@laptop' | sudo tee -a /etc/ssh/authorized_keys.d/noc
    ```

3.  **Remove Users:**
    Manually delete the line from `/etc/ssh/authorized_keys.d/noc` and run `sudo userdel -r noc-alice`.

### Option 2: Ansible Deployment (Fleet Management)
Use this to manage multiple gateways across many servers.

1.  **Directory Layout:**
    * `ansible/manage_keys.yml`: Main playbook.
    * `ansible/tasks/deploy_gateway.yml`: Logic to deploy a single gateway.
    * `ansible/public_keys/`: Directory of keys organized by gateway.
        * `noc/` -> Keys for the NOC team.
        * `sre/` -> Keys for the SRE team.

2.  **Usage:**
    * **Add Keys:** Create `ansible/public_keys/<gateway>/<user>.keys`.
    * **Run Playbook:** `ansible-playbook ansible/manage_keys.yml`.

3.  **Automatic Cleanup:**
    * If you delete a key file locally and run the playbook, Ansible will automatically remove the key from the server AND delete the corresponding system user (`noc-alice`) and home directory.

## 3. Security Features

* **Strict File Permissions:** `authorized_keys` stored in `/etc/ssh/authorized_keys.d/` and owned by `root`.
* **Numeric ID Checks:** Script verifies UID 0 ownership to avoid name spoofing.
* **Path Safety:** Uses `readlink -f` to resolve paths and block symlinks.
* **Audit Logging:** Logs the SHA fingerprint of the key used for access.
* **Regex Verification:** Enforces that the authentication key matches the authorized command structure.
