# encoding: UTF-8

control 'C-2.2.3' do
  title 'Ensure the NGINX service account has an invalid shell'
  desc  "
    The NGINX service account must be configured with an invalid login shell to prevent interactive access.

    The NGINX service account is strictly for running daemon processes. Assigning it a valid login shell (like `/bin/bash`) unnecessarily expands the attack surface. If an attacker compromises the account credentials (or adds an SSH key), a valid shell facilitates interactive system access. Setting the shell to `/sbin/nologin` or `/bin/false` ensures that even with valid credentials, the system immediately rejects a login attempt.
  "
  desc  'rationale', "
    The NGINX service account must be configured with an invalid login shell to prevent interactive access.

    The NGINX service account is strictly for running daemon processes. Assigning it a valid login shell (like `/bin/bash`) unnecessarily expands the attack surface. If an attacker compromises the account credentials (or adds an SSH key), a valid shell facilitates interactive system access. Setting the shell to `/sbin/nologin` or `/bin/false` ensures that even with valid credentials, the system immediately rejects a login attempt.
  "
  desc  'check', "
    1. Identify the User:
    ```
    nginx -T 2>/dev/null | grep -i \"^user\"
    ```
    (Note the user, e.g., `nginx`)

    2. Verify Shell:

    Run the following command to inspect the configured shell for the identified user:
    ```
    getent passwd nginx
    ```
    (Replace `nginx` with the actual user found in step 1)

    Evaluation:

    Examine the last field of the output (the shell).

    - PASS: The shell is set to `/sbin/nologin`, `/bin/nologin`, or `/bin/false`.
    - FAIL: The shell is set to `/bin/bash`, `/bin/sh`, or any other interactive shell listed in `/etc/shells`.

    Example Output (PASS):
    ```
    nginx:x:999:988:nginx user:/nonexistent:/usr/sbin/nologin
    ```
  "
  desc  'fix', "
    Change the login shell for the identified user to `/sbin/nologin`:

    ```
    usermod -s /sbin/nologin nginx
    ```

    (Replace `nginx` with the actual user)
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '2.2.3'
  tag cis_rid:               '2.2.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020203r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  user = input('nginx_service_user')
  if passwd.users(user).entries.empty?
    describe "nginx service account #{user} — /etc/passwd lookup" do
      skip "not-applicable: user `#{user}` absent from /etc/passwd on the scan target. In distroless images this is expected (the process runs as a numeric uid without a matching passwd entry)."
    end
  else
    acceptable_shells = ['/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/usr/bin/false']
    describe passwd.users(user) do
      its('shells') { should all(be_in acceptable_shells) }
    end
  end
end
