# encoding: UTF-8

control 'C-2.2.1' do
  title 'Ensure that NGINX is run using a non-privileged, dedicated service account'
  desc  "
    The NGINX master process typically runs as `root` to bind to privileged ports and manage resources, but it spawns worker processes to handle the actual client traffic. The `user` directive in the main configuration designates the operating system account under which these worker processes run.

    Running worker processes under a non-privileged, dedicated service account limits the damage an attacker can cause in the event the NGINX process is compromised. This account should be exclusively dedicated to NGINX, have no login capabilities, and possess no elevated system privileges.

    If an attacker successfully exploits a vulnerability in a worker process (e.g., via a buffer overflow or Remote Code Execution), they inherit the permissions of the user account running that process. Using a privileged account like `root` significantly increases the risk of lateral movement. A dedicated, locked-down service account ensures that an attacker cannot access other services, modify sensitive system files, or easily escalate privileges, effectively reducing the impact of the compromise.
  "
  desc  'rationale', "
    The NGINX master process typically runs as `root` to bind to privileged ports and manage resources, but it spawns worker processes to handle the actual client traffic. The `user` directive in the main configuration designates the operating system account under which these worker processes run.

    Running worker processes under a non-privileged, dedicated service account limits the damage an attacker can cause in the event the NGINX process is compromised. This account should be exclusively dedicated to NGINX, have no login capabilities, and possess no elevated system privileges.

    If an attacker successfully exploits a vulnerability in a worker process (e.g., via a buffer overflow or Remote Code Execution), they inherit the permissions of the user account running that process. Using a privileged account like `root` significantly increases the risk of lateral movement. A dedicated, locked-down service account ensures that an attacker cannot access other services, modify sensitive system files, or easily escalate privileges, effectively reducing the impact of the compromise.
  "
  desc  'check', "
    1. Identify Configured User:

    Inspect the running configuration to find the user directive:
    ```
    nginx -T 2>/dev/null | grep -i \"^user\"
    ```
    Evaluation: Verify that a specific user is defined (e.g., `user nginx;` or `user www-data;`). If missing, NGINX might run as `nobody` or the user used at compile time.

    2. Verify User Privileges:

    Check the UID and group membership of the identified user (e.g., `nginx`):
    ```
    id nginx
    ```
    Evaluation:

    - Ensure uid is not 0 (root).
    - Ensure the user is not a member of privileged groups (like `root`, `wheel`, `sudo`).

    3. Check Sudo Access:

    Ensure the user cannot execute commands via `sudo`:
    ```
    sudo -l -U nginx
    ```
    Evaluation: Output should indicate \"`User nginx is not allowed to run sudo`\".
  "
  desc  'fix', "
    1. Create/Harden User (if missing):

    If no user exists, create a system user with a no login shell:
    ```
    useradd -r -d /var/cache/nginx -s /sbin/nologin nginx
    ```
    2. Configure NGINX:

    Set the user directive in the main context of `nginx.conf`:
    ```
    user nginx;
    ```
    3. Lock User Account:

    Ensure the account cannot be used for login:

    ```
    usermod -s /sbin/nologin nginx
    usermod -L nginx
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '2.2.1'
  tag cis_rid:               '2.2.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020201r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  described_user = Array(nginx_conf(input('nginx_conf_path')).params['user']).flatten.first

  describe 'nginx.conf `user` directive matches nginx_service_user input' do
    subject { described_user }
    it { should eq input('nginx_service_user') }
  end
end
