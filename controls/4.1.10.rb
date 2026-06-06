# encoding: UTF-8

control 'C-4.1.10' do
  title 'Ensure the upstream traffic server certificate is trusted'
  desc  "
    When acting as a reverse proxy, NGINX must be configured to function as a secure TLS client. This requires validating the identity of the upstream server by verifying its certificate against a trusted Certificate Authority (CA). Furthermore, NGINX must ensure that the hostname of the upstream server matches the name (Subject Name / SAN) within the certificate itself.

    Without proper validation, NGINX blindly trusts the identity of the upstream server, making it vulnerable to man-in-the-middle (MitM) attacks within the internal network. An attacker could impersonate a legitimate backend service and intercept sensitive traffic. By enforcing certificate validation (`proxy_ssl_verify`) and hostname verification (`proxy_ssl_name`), NGINX guarantees that it is communicating with the intended, authentic upstream server.
  "
  desc  'rationale', "
    When acting as a reverse proxy, NGINX must be configured to function as a secure TLS client. This requires validating the identity of the upstream server by verifying its certificate against a trusted Certificate Authority (CA). Furthermore, NGINX must ensure that the hostname of the upstream server matches the name (Subject Name / SAN) within the certificate itself.

    Without proper validation, NGINX blindly trusts the identity of the upstream server, making it vulnerable to man-in-the-middle (MitM) attacks within the internal network. An attacker could impersonate a legitimate backend service and intercept sensitive traffic. By enforcing certificate validation (`proxy_ssl_verify`) and hostname verification (`proxy_ssl_name`), NGINX guarantees that it is communicating with the intended, authentic upstream server.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for the three required directives within the relevant proxy `location` block:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(proxy_ssl_verify|proxy_ssl_trusted_certificate|proxy_ssl_name)'
    ```
    Verify that the output contains the following directives:

    - `proxy_ssl_verify               on;`
    - `proxy_ssl_trusted_certificate  /path/to/ca.crt;`
    - `proxy_ssl_name                 your-upstream-hostname.com;`

    If any of these three directives are missing, this recommendation is not fully implemented. Additionally, manually verify that the certificate referenced by `proxy_ssl_trusted_certificate` is the correct, valid CA certificate for your upstream services.
  "
  desc  'fix', "
    To securely configure upstream validation, you must obtain the CA certificate that signed your upstream server's certificate.

    1. Place the CA certificate (e.g., `upstream_ca.crt`) in a secure directory on the NGINX server (e.g., `/etc/nginx/ssl/`).
    2. In the `location` block that proxies traffic, add the following three directives. The `proxy_ssl_name` must match the hostname used in the `proxy_pass` directive.

    ```
    location /api/ {
        proxy_pass                     https://your-upstream-hostname.com;
        # 1. Enable verification
        proxy_ssl_verify               on;

        # 2. Specify the CA to trust for verification
        proxy_ssl_trusted_certificate  /etc/nginx/ssl/upstream_ca.crt;

        # 3. Verify the certificate's name matches the server's hostname
        proxy_ssl_name                 your-upstream-hostname.com;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.10'
  tag cis_rid:               '4.1.10'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040110r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  conf = nginx_conf(input('nginx_conf_path'))
  proxy_pass_locations = conf.http.servers.flat_map(&:locations).select { |l| !Array(l.params['proxy_pass']).empty? }

  if proxy_pass_locations.empty?
    describe 'NGINX upstream certificate trust (proxy_ssl_verify)' do
      skip 'not-applicable: no proxy_pass directives — NGINX is not acting as a reverse proxy.'
    end
  else
    offenders = proxy_pass_locations.each_with_object([]) do |loc, acc|
      verify = Array(loc.params['proxy_ssl_verify']).flatten.first.to_s
      trusted = Array(loc.params['proxy_ssl_trusted_certificate']).flatten.first
      acc << loc.params.to_s unless verify == 'on' && trusted
    end
    describe 'NGINX proxy_pass locations not enforcing proxy_ssl_verify on with proxy_ssl_trusted_certificate set' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
