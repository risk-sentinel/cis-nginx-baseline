# encoding: UTF-8

control 'C-4.1.7' do
  title 'Ensure Online Certificate Status Protocol (OCSP) stapling is enabled'
  desc  "
    OCSP stapling allows a server to efficiently deliver certificate revocation information to the client, improving performance and privacy. The server caches the OCSP response from the Certificate Authority (CA), eliminating the need for the client to make a separate connection. For robust security, certificates should be issued with the OCSP Must-Staple extension, which transforms the traditional \"soft-fail\" behavior into a \"hard-fail,\" ensuring clients always receive and validate a current revocation status.

    OCSP stapling is a critical mechanism for distributing certificate revocation status. Without it, clients might not be aware that a server's certificate has been compromised, allowing for potential man-in-the-middle attacks. The OCSP Must-Staple extension is essential as it mitigates the inherent weakness of optional OCSP (\"soft-fail\"), where a browser might proceed with a connection if it doesn't receive a staple. By enforcing a \"hard-fail\", Must-Staple ensures that a compromised certificate can be reliably blocked.
  "
  desc  'rationale', "
    OCSP stapling allows a server to efficiently deliver certificate revocation information to the client, improving performance and privacy. The server caches the OCSP response from the Certificate Authority (CA), eliminating the need for the client to make a separate connection. For robust security, certificates should be issued with the OCSP Must-Staple extension, which transforms the traditional \"soft-fail\" behavior into a \"hard-fail,\" ensuring clients always receive and validate a current revocation status.

    OCSP stapling is a critical mechanism for distributing certificate revocation status. Without it, clients might not be aware that a server's certificate has been compromised, allowing for potential man-in-the-middle attacks. The OCSP Must-Staple extension is essential as it mitigates the inherent weakness of optional OCSP (\"soft-fail\"), where a browser might proceed with a connection if it doesn't receive a staple. By enforcing a \"hard-fail\", Must-Staple ensures that a compromised certificate can be reliably blocked.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for the four required directives:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(ssl_stapling|ssl_stapling_verify|ssl_trusted_certificate|resolver)'
    ```
    Verify that the output contains the following directives with appropriate values within the relevant `http` or `server` blocks:

    - `ssl_stapling             on;`
    - `ssl_stapling_verify      on;`
    - `ssl_trusted_certificate  /path/to/your/chain.pem;`
    - `resolver                 A.B.C.D;`

    If any of these four directives are missing, this recommendation is not fully implemented.
  "
  desc  'fix', "
    Follow this procedure to enable a robust OCSP stapling configuration:

    1. When issuing a certificate, request that the OCSP Must-Staple extension be included.
    2. Edit your NGINX configuration to include all four necessary directives. The `ssl_trusted_certificate` must point to a file containing your root and intermediate certificates. The resolver must be set to one or more trusted DNS resolvers.

    ```
    # Example for a server block
    server {
        # ... other directives ...

        # OCSP Stapling
        ssl_stapling             on;
        ssl_stapling_verify      on;

        # Path to the certificate chain (Root CA + Intermediates) for verification
        ssl_trusted_certificate  /etc/nginx/ssl/full_chain.pem;

        # DNS resolver for NGINX to query the CA's OCSP server
        resolver                 8.8.8.8  1.1.1.1  valid=300s;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.7'
  tag cis_rid:               '4.1.7'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040107r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  conf = nginx_conf(input('nginx_conf_path'))
  stapling_values = Array(nginx_http_values(conf, 'ssl_stapling')).flatten.map(&:to_s)
  verify_values = Array(nginx_http_values(conf, 'ssl_stapling_verify')).flatten.map(&:to_s)
  conf.http.servers.each do |s|
    stapling_values.concat(Array(s.params['ssl_stapling']).flatten.map(&:to_s))
    verify_values.concat(Array(s.params['ssl_stapling_verify']).flatten.map(&:to_s))
  end

  has_tls = !Array(nginx_http_values(conf, 'ssl_certificate')).empty? ||
            conf.http.servers.any? { |s| !Array(s.params['ssl_certificate']).empty? }

  termination = input('nginx_tls_termination')
  disp = tls_termination_disposition(termination, has_tls)
  impact 0.0 if disp == :na

  if disp == :na
    describe 'NGINX OCSP stapling' do
      skip "not-applicable: nginx_tls_termination=#{termination} — NGINX does not terminate TLS here; validate it at the terminating layer (the load balancer / compute / fargate ALB TLS controls)."
    end
  elsif disp == :missing
    describe 'NGINX must terminate TLS when nginx_tls_termination=nginx (4.1.7)' do
      subject { has_tls }
      it { is_expected.to be_truthy }
    end
  else
    describe 'NGINX ssl_stapling enabled (CIS 4.1.7)' do
      subject { stapling_values.any? { |v| v == 'on' } }
      it { should eq true }
    end
    describe 'NGINX ssl_stapling_verify enabled (CIS 4.1.7)' do
      subject { verify_values.any? { |v| v == 'on' } }
      it { should eq true }
    end
  end
end
