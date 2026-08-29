# encoding: UTF-8

control 'C-1.2.2' do
  title 'Ensure the latest software package is installed'
  desc  "
    As new security vulnerabilities are discovered, the corresponding fixes are implemented by your NGINX software package provider. Installing the latest software version ensures these fixes are available on your system.

    Up-to-date software provides the best possible protection against exploitation of security vulnerabilities, such as the execution of malicious code.
  "
  desc  'rationale', "
    As new security vulnerabilities are discovered, the corresponding fixes are implemented by your NGINX software package provider. Installing the latest software version ensures these fixes are available on your system.

    Up-to-date software provides the best possible protection against exploitation of security vulnerabilities, such as the execution of malicious code.
  "
  desc  'check', "
    To verify your NGINX package is up to date, run the following command (example): 

    Redhat:

    ```
    dnf info nginx
    ```
  "
  desc  'fix', "
    To install the latest NGINX package, run the following command (example):

    Redhat:

    ```
    dnf update nginx -y
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-12', 'MP-6 a', 'SI-2 a']
  tag nist_r4:               ['MP-6 a', 'SI-12', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001028', 'CCI-001225']
  tag cis_number:            '1.2.2'
  tag cis_rid:               '1.2.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-010202r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        true


  min_version = input('nginx_min_version').to_s.strip
  if min_version.empty?
    describe 'NGINX package currency (1.2.2)' do
      skip 'attestation-required: set nginx_min_version (e.g. "1.27.0") to enable an automated version-floor check; otherwise "latest" is an image-supply-chain bake-time decision the operator attests.'
    end
  else
    out = command('nginx -v')
    ver = (out.stderr.to_s + out.stdout.to_s)[%r{nginx/(\S+)}, 1]
    describe "NGINX version (1.2.2 — floor #{min_version})" do
      it 'is detectable from `nginx -v`' do
        expect(ver).not_to be_nil
      end
      it "is >= #{min_version}" do
        expect(Gem::Version.new(ver)).to be >= Gem::Version.new(min_version) if ver
      end
    end
  end
end
