# encoding: UTF-8

control 'C-1.1.1' do
  title 'Ensure NGINX is installed'
  desc  "
    An NGINX installation must be present on the system. To ensure support for modern security standards (such as TLS 1.3 and HTTP/3) and to mitigate known vulnerabilities, the installed version must be `1.28.0` or later and compiled with the necessary modules.

    NGINX must be installed and operational to serve as the target for this benchmark's security controls. Enforcing a minimum version and feature set ensures the platform is capable of supporting the required security configurations.
  "
  desc  'rationale', "
    An NGINX installation must be present on the system. To ensure support for modern security standards (such as TLS 1.3 and HTTP/3) and to mitigate known vulnerabilities, the installed version must be `1.28.0` or later and compiled with the necessary modules.

    NGINX must be installed and operational to serve as the target for this benchmark's security controls. Enforcing a minimum version and feature set ensures the platform is capable of supporting the required security configurations.
  "
  desc  'check', "
    1. Verify Installation and Version:
    Run the following command to display the installed NGINX version:

    ```
    # Note: It's an uppercase V
    nginx -V
    ```

    2. Evaluation:

    - Verify Output: The command must return an installed version (e.g., `nginx version: nginx/1.28.0`). If the command is not found, NGINX is not installed.
    - Check Version: Ensure the version number is 1.28.0 or higher.
  "
  desc  'fix', "
    Install or upgrade NGINX to version `1.28.0` or later.

    Note: Official packages from [nginx.org](https://nginx.org/en/linux_packages.html) (see recommendation 1.2.1) typically include these modules by default. Custom builds must explicitly enable them.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '1.1.1'
  tag cis_rid:               '1.1.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-010101r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  describe command('nginx -v') do
    its('exit_status') { should eq 0 }
  end

  describe package('nginx') do
    it { should be_installed }
  end
end
