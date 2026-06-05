# encoding: UTF-8

control 'C-2.2.2' do
  title 'Ensure the NGINX service account is locked'
  desc  "
    The NGINX service account must not have a usable password and should be explicitly locked in the system's shadow file to prevent direct login or password-based privilege escalation.

    As a defense-in-depth measure, the NGINX service account should be explicitly locked. This prevents password-based logins and blocks adversaries from using the account for lateral movement, even if they manage to change the account's shell configuration.

    In a properly hardened environment, there is no operational need for any user to log in as `nginx`. Administrative tasks requiring the NGINX identity should be performed using `sudo` (e.g., `sudo -u nginx`), which utilizes the administrator's credentials rather than the service account's password.
  "
  desc  'rationale', "
    The NGINX service account must not have a usable password and should be explicitly locked in the system's shadow file to prevent direct login or password-based privilege escalation.

    As a defense-in-depth measure, the NGINX service account should be explicitly locked. This prevents password-based logins and blocks adversaries from using the account for lateral movement, even if they manage to change the account's shell configuration.

    In a properly hardened environment, there is no operational need for any user to log in as `nginx`. Administrative tasks requiring the NGINX identity should be performed using `sudo` (e.g., `sudo -u nginx`), which utilizes the administrator's credentials rather than the service account's password.
  "
  desc  'check', "
    1. Identify the User:
    ```
    nginx -T 2>/dev/null | grep -i \"^user\"
    ```
    (Note the user, e.g., `nginx`)

    2. Check Lock Status:

    Run the following command for the identified user:
    ```
    passwd -S nginx
    ```
    Evaluation:

    Verify that the output indicates a locked status:

    - RHEL: Shows `LK` or `Password locked`.
    - Debian/Ubuntu: Shows `L`.
  "
  desc  'fix', "
    Lock the account using the `passwd` command:
    ```
    passwd -l nginx
    ```
    (Replace `nginx` with the actual service user found in step 1)
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.2.2'
  tag cis_rid:               '2.2.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020202r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  user = input('nginx_service_user')
  if shadow.users(user).entries.empty?
    describe "nginx service account #{user} — /etc/shadow lookup" do
      skip "pending-resource: /etc/shadow is unreadable from the scan context (common in distroless / scratch-based NGINX container images where the shadow file is stripped at build time). Run with `-t docker://<container>` against a container image that retains shadow to enable this check."
    end
  else
    describe shadow.users(user) do
      its('passwords') { should all(match(/\A(!|\*|!!)/)) }
    end
  end
end
