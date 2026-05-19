# encoding: UTF-8

control 'C-2.3.3' do
  title 'Ensure the NGINX process ID (PID) file is secured'
  desc  "
    The `PID` file stores the main process ID of the nginx process. This file should be protected from unauthorized modification.

    The `PID` file should be owned by `root` and the group `root`. It should also be readable to everyone, but only writable by `root` (permissions `644`). This will prevent unauthorized modification of the `PID` file, which could cause a denial of service.
  "
  desc  'rationale', "
    The `PID` file stores the main process ID of the nginx process. This file should be protected from unauthorized modification.

    The `PID` file should be owned by `root` and the group `root`. It should also be readable to everyone, but only writable by `root` (permissions `644`). This will prevent unauthorized modification of the `PID` file, which could cause a denial of service.
  "
  desc  'check', "
    1. Identify PID File Location:

    Run `nginx -V` and look for the `--pid-path` argument to confirm the location (e.g., `/run/nginx.pid` or `/var/run/nginx.pid`).

    2. Verify Ownership and Permissions:

    Run the following command (substituting the identified path):
    ```
    stat -Lc \"%U:%G %a\" /run/nginx.pid
    ```
    Evaluation:

    - Ownership: Must be `root:root`.
    - Permissions: Must be `644` (`rw-r--r--`) or more restrictive.
  "
  desc  'fix', "
    Set the correct ownership and permissions for the `PID` file (replace path as needed):

    ```
    chown root:root /run/nginx.pid
    chmod 644       /run/nginx.pid
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.3.3'
  tag cis_rid:               '2.3.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020303r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  pid_candidates = ['/var/run/nginx.pid', '/run/nginx.pid']
  pid_file = pid_candidates.find { |p| file(p).exist? }
  if pid_file.nil?
    describe 'NGINX PID file' do
      skip 'not-applicable: no PID file found at /var/run/nginx.pid or /run/nginx.pid. NGINX is likely not running on this target or was started with `--pid-path` / foreground mode.'
    end
  else
    describe file(pid_file) do
      it { should be_owned_by 'root' }
      its('group') { should eq 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end
