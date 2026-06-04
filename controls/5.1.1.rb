# encoding: UTF-8

control 'C-5.1.1' do
  title 'Ensure allow and deny filters limit access to specific IP addresses'
  desc  "
    Access control based on IP addresses is a fundamental defense-in-depth mechanism. By using NGINX's `allow` and `deny` directives, access to the entire server or specific `location` blocks can be restricted to trusted network sources, such as internal subnets, specific hosts, or VPN ranges. This is particularly effective for protecting non-public administrative interfaces or internal APIs from the public internet.

    Applying the principle of least privilege at the network layer is a highly effective security measure. By explicitly defining which IP addresses or CIDR ranges are permitted to access sensitive resources and implicitly denying all others with `deny all;`, the attack surface is significantly reduced. This prevents unauthorized network segments from even attempting to exploit potential application-layer vulnerabilities.
  "
  desc  'rationale', "
    Access control based on IP addresses is a fundamental defense-in-depth mechanism. By using NGINX's `allow` and `deny` directives, access to the entire server or specific `location` blocks can be restricted to trusted network sources, such as internal subnets, specific hosts, or VPN ranges. This is particularly effective for protecting non-public administrative interfaces or internal APIs from the public internet.

    Applying the principle of least privilege at the network layer is a highly effective security measure. By explicitly defining which IP addresses or CIDR ranges are permitted to access sensitive resources and implicitly denying all others with `deny all;`, the attack surface is significantly reduced. This prevents unauthorized network segments from even attempting to exploit potential application-layer vulnerabilities.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for `allow` and `deny` rules:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(allow|deny)'
    ```
    Then, manually review the active rules within the `http`, `server`, or `location` blocks. Verify that the configured IP addresses and CIDR ranges align with the documented list of trusted sources and that a `deny all;` rule is present to enforce a default-deny policy.
  "
  desc  'fix', "
    Identify the specific `location` block you wish to protect (e.g., an admin login page or internal stats). Compile a list of trusted source IP addresses and network ranges. Add `allow` directives for each trusted source, followed by a final `deny all;` directive. NGINX processes rules in order, and stops at the first match.

    ```
    location /admin_login/ {
        # Allow a specific monitoring server
        allow 192.168.1.100;

        # Allow the internal office network range
        allow 10.20.30.0/24;

        # Deny all other access to this location
        deny all;

        # ... other directives for the admin location, e.g., proxy_pass ...
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-4', 'SI-4 (5)']
  tag cci:                   ['CCI-001414', 'CCI-002663']
  tag cis_number:            '5.1.1'
  tag cis_rid:               '5.1.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050101r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'
  tag exec_validated:        false


  if !input('nginx_require_ip_filtering')
    describe 'NGINX IP allow/deny access control (5.1.1)' do
      skip 'attestation-required: the access map (admin paths, partner CIDRs, internal-only locations) is consumer-policy-specific; set nginx_require_ip_filtering: true to assert at least one allow/deny directive is present, or attest the access map per workload.'
    end
  else
    conf = nginx_conf(input('nginx_conf_path'))
    directives = Array(nginx_http_values(conf, 'allow')) + Array(nginx_http_values(conf, 'deny'))
    conf.http.servers.each do |s|
      directives += Array(s.params['allow']) + Array(s.params['deny'])
      s.locations.each { |l| directives += Array(l.params['allow']) + Array(l.params['deny']) }
    end
    directives = directives.flatten.reject { |v| v.to_s.empty? }
    describe 'NGINX allow/deny access directives (5.1.1)' do
      subject { directives.size }
      it 'has at least one allow/deny filter when IP filtering is required' do
        expect(directives.size).to be > 0
      end
    end
  end
end
