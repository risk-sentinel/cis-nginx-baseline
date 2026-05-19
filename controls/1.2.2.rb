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
  tag nist:                  ['SI-12', 'MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001028', 'CCI-001225']
  tag cis_number:            '1.2.2'
  tag cis_rid:               '1.2.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-010202r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip 'Requires manual review and attestation provided for this control ("latest" NGINX version is a container-image bake-time decision enforced by the image supply-chain pipeline; the running workload has no notion of "latest" to assert against)'
  end
end
