# encoding: UTF-8

control 'C-2.3.1' do
  title 'Ensure NGINX directories and files are owned by root'
  desc  "
    The NGINX configuration directory and all contained files must be owned by the `root` user and group to prevent unauthorized modification.

    The NGINX configuration controls the security posture of the web server. If a non-privileged user (including the `nginx` worker user) can modify these files, they can trivially escalate privileges (e.g., by loading a malicious module or changing the `user` directive to `root`). Ensuring that only `root` owns these files guarantees that configuration changes require administrative privileges.
  "
  desc  'rationale', "
    The NGINX configuration directory and all contained files must be owned by the `root` user and group to prevent unauthorized modification.

    The NGINX configuration controls the security posture of the web server. If a non-privileged user (including the `nginx` worker user) can modify these files, they can trivially escalate privileges (e.g., by loading a malicious module or changing the `user` directive to `root`). Ensuring that only `root` owns these files guarantees that configuration changes require administrative privileges.
  "
  desc  'check', "
    1. Identify Configuration Directory:

    Run `nginx -V` and look for `--conf-path` to find the main configuration file location (e.g., `/etc/nginx/nginx.conf`). The directory containing this file is the target.

    2. Verify Ownership:

    Run the following command to audit the ownership of the configuration directory and its contents:
    ```
    find /etc/nginx -name \"*\" \\( -not -user root -o -not -group root \\) -exec ls -ld {} \\;
    ```
    (Replace `/etc/nginx` with the actual configuration path in case it is different)

    Evaluation:

    - PASS: The command produces no output. All files are owned by `root:root`.
    - FAIL: The command lists files owned by other users (e.g., `nginx` or a developer account).
  "
  desc  'fix', "
    Set the ownership of the NGINX configuration directory and files to `root`:
    ```
    chown -R root:root /etc/nginx
    ```
    (Replace `/etc/nginx` with the actual configuration path in case it is different)

    Note: Ensure that this does not break access to specific files if you have a custom setup where external processes need write access.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.3.1'
  tag cis_rid:               '2.3.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020301r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  offenders = []
  if file('/etc/nginx').directory?
    command('find /etc/nginx -type f -o -type d 2>/dev/null').stdout.each_line do |line|
      p = line.strip
      next if p.empty?
      f = file(p)
      offenders << "#{p}:owner=#{f.owner}" unless f.owner == 'root'
      offenders << "#{p}:group=#{f.group}" unless f.group == 'root'
    end
  end

  describe 'NGINX files/dirs not owned by root:root' do
    subject { offenders }
    it { should be_empty }
  end
end
