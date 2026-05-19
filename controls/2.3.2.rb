# encoding: UTF-8

control 'C-2.3.2' do
  title 'Ensure access to NGINX directories and files is restricted'
  desc  "
    The NGINX configuration directory (`/etc/nginx` or equivalent) and its contents should have restrictive permissions to enforce the principle of least privilege.

    - Directories should be accessible only by the `root` user and the `root` group (and potentially read/execute by the group), but not by others.
    - Files should be readable/writable by `root` and readable by the group, but inaccessible to others.

    Restrictive file permissions prevent unauthorized users on the system from viewing sensitive configuration details, such as backend IP addresses, routing logic, or loaded module paths. By removing \"world\" access (permissions for \"other\"), we ensure that only administrators (via `sudo`) can interact with the web server configuration. This is a fundamental defense against information disclosure.
  "
  desc  'rationale', "
    The NGINX configuration directory (`/etc/nginx` or equivalent) and its contents should have restrictive permissions to enforce the principle of least privilege.

    - Directories should be accessible only by the `root` user and the `root` group (and potentially read/execute by the group), but not by others.
    - Files should be readable/writable by `root` and readable by the group, but inaccessible to others.

    Restrictive file permissions prevent unauthorized users on the system from viewing sensitive configuration details, such as backend IP addresses, routing logic, or loaded module paths. By removing \"world\" access (permissions for \"other\"), we ensure that only administrators (via `sudo`) can interact with the web server configuration. This is a fundamental defense against information disclosure.
  "
  desc  'check', "
    1. Identify Configuration Directory:

    Run `nginx -V` and identify the `--conf-path` to determine the configuration root (e.g., `/etc/nginx`).

    2. Audit Directory Permissions:

    Run the following command to find directories with loose permissions:
    ```
    find /etc/nginx -type d -exec stat -Lc \"%n %a\" {} +
    ```
    Evaluation:

    Verify that the output shows permissions of `750` (`drwxr-x---`) or more restrictive (e.g., `700`).

    - Standard: `755` (`drwxr-xr-x`) allows world read/execute.
    - Hardened Target: `750` or `700`.

    3. Audit File Permissions:

    Run the following command to find files with loose permissions:
    ```
    find /etc/nginx -type f -exec stat -Lc \"%n %a\" {} +
    ```
    Evaluation:

    Verify that the output shows permissions of `640` (`-rw-r-----`) or more restrictive (e.g., `600`).

    - Standard: `644` (`-rw-r--r--`) allows world read.
    - Hardened Target: `640` or `600`.
  "
  desc  'fix', "
    To restrict access to the NGINX configuration directory and files, execute the following commands:

    1. Restrict Directories (`750`):

    Allow owner (`root`) full access, group read/execute, deny others.
    ```
    find /etc/nginx -type d -exec chmod 750 {} +
    ```
    2. Restrict Files (`640`):
    Allow owner (`root`) read/write, group read, deny others.
    ```
    find /etc/nginx -type f -exec chmod 640 {} +
    ```
    Note: Private keys (e.g., `.key` files) require even stricter permissions (`400` or `600`) and should be addressed separately or manually verified here.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.3.2'
  tag cis_rid:               '2.3.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020302r1_rule'
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
      mode = f.mode.to_s(8).rjust(4, '0')
      other_bits = mode[-1].to_i
      group_bits = mode[-2].to_i
      offenders << "#{p}:mode=#{mode}" if (other_bits & 0o2) != 0 || (group_bits & 0o2) != 0
    end
  end

  describe 'NGINX files/dirs with group- or world-writable bits' do
    subject { offenders }
    it { should be_empty }
  end
end
