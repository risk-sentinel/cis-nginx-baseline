# encoding: UTF-8

control 'C-4.1.4' do
  title 'Ensure only modern TLS protocols are used'
  desc  "
    Only modern TLS protocols should be enabled in NGINX for all client connections and upstream connections. Removing legacy TLS and SSL protocols (SSL 3.0, TLS 1.0, 1.1 and 1.2), and enable stable TLS protocols (TLS 1.3), ensures users are able to take advantage of strong security capabilities and protects them from insecure legacy protocols.

    Why disable SSL 3.0:
    The [POODLE Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2014-3566) allowed attackers to exploit SSL 3.0 to obtain cleartext information by exploiting weaknesses in CBC in 2014. SSL 3.0 is also no longer FIPS 140-2 compliant.

    Why disable TLS 1.0:
    TLS 1.0 was deprecated from use when PCI DSS Compliance mandated that it not be used for any applications processing credit card numbers in June 2018. TLS 1.0 does not make use of modern protections, and almost all user agents that do not support TLS 1.2 or higher are no longer supported by their vendor.

    Why disable TLS 1.1:
    Because of the increased security associated with higher versions of TLS, TLS 1.0 should be disabled. Modern browsers will begin to flag TLS 1.1 as deprecated in early 2019.

    Why disable TLS 1.2:
    While robust for its time, TLS 1.2's complexity allows for weak configurations, including cipher suites that lack Perfect Forward Secrecy. TLS 1.3 eliminates this risk by mandating PFS and removing outdated cryptographic primitives. Acknowledging this, NIST SP 800-52 Rev. 2 allows for TLS 1.2 to be disabled if it is not required for interoperability, positioning TLS 1.3 as the sole recommended protocol for modern, secure environments.

    Why enable TLS 1.3:
    TLS 1.3 improves security by removing several insecure cipher suites by default and adding several more secure algorithms. All public-key exchange mechanisms support perfect forward secrecy in this version of TLS. Additionally, TLS 1.3 makes drastic performance improvements by removing a full round trip in the TLS handshake.
  "
  desc  'rationale', "
    Only modern TLS protocols should be enabled in NGINX for all client connections and upstream connections. Removing legacy TLS and SSL protocols (SSL 3.0, TLS 1.0, 1.1 and 1.2), and enable stable TLS protocols (TLS 1.3), ensures users are able to take advantage of strong security capabilities and protects them from insecure legacy protocols.

    Why disable SSL 3.0:
    The [POODLE Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2014-3566) allowed attackers to exploit SSL 3.0 to obtain cleartext information by exploiting weaknesses in CBC in 2014. SSL 3.0 is also no longer FIPS 140-2 compliant.

    Why disable TLS 1.0:
    TLS 1.0 was deprecated from use when PCI DSS Compliance mandated that it not be used for any applications processing credit card numbers in June 2018. TLS 1.0 does not make use of modern protections, and almost all user agents that do not support TLS 1.2 or higher are no longer supported by their vendor.

    Why disable TLS 1.1:
    Because of the increased security associated with higher versions of TLS, TLS 1.0 should be disabled. Modern browsers will begin to flag TLS 1.1 as deprecated in early 2019.

    Why disable TLS 1.2:
    While robust for its time, TLS 1.2's complexity allows for weak configurations, including cipher suites that lack Perfect Forward Secrecy. TLS 1.3 eliminates this risk by mandating PFS and removing outdated cryptographic primitives. Acknowledging this, NIST SP 800-52 Rev. 2 allows for TLS 1.2 to be disabled if it is not required for interoperability, positioning TLS 1.3 as the sole recommended protocol for modern, secure environments.

    Why enable TLS 1.3:
    TLS 1.3 improves security by removing several insecure cipher suites by default and adding several more secure algorithms. All public-key exchange mechanisms support perfect forward secrecy in this version of TLS. Additionally, TLS 1.3 makes drastic performance improvements by removing a full round trip in the TLS handshake.
  "
  desc  'check', "
    You can verify which SSL/TLS protocols your server uses by issuing the below command to see the configured cipher suites on the server. If anything older than TLS 1.3 is implemented or nothing appears, this recommendation is not implemented.

    ```
    grep -ir ssl_protocol /etc/nginx
    ```

    Note: Depending on your configuration, you may see different results. The directive `ssl_protocols` should always be part of your server block. If your NGINX server is also a proxy or load balancer, you should also check for the presence of the `proxy_ssl_protocols` directive as part of the location block of your nginx configuration. This ensures your proxy follows a specific set of negotiation rules for encrypting traffic with your upstream server.
  "
  desc  'fix', "
    Run the following commands to change your `ssl_protocols` if they are already configured. This remediation advice assumes your nginx configuration file does not include server configuration outside of `/etc/nginx/nginx.conf`. You may have to also inspect the include files in your `nginx.conf` to ensure this is properly implemented.

    Web Server:

    ```
    sed -i \"s/ssl_protocols[^;]*;/ssl_protocols TLSv1.3;/\" /etc/nginx/nginx.conf
    ```

    Proxy:

    ```
    sed -i \"s/proxy_ssl_protocols[^;]*;/proxy_ssl_protocols TLSv1.3;/\" /etc/nginx/nginx.conf
    ```

    If your `ssl_protocols` are not already configured, this can be accomplished manually by opening your web server or proxy server configuration file and manually adding the directives.

    Web Server:
    ```
    server {
        ssl_protocols TLSv1.3;
    }
    ```

    Proxy:

    ```
    location / {
          proxy_pass          cisecurity.org;
          proxy_ssl_protocols TLSv1.3;
        }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.4'
  tag cis_rid:               '4.1.4'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040104r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  protocols = Array(conf.http.params['ssl_protocols']).flatten.map(&:to_s)
  conf.http.servers.each do |s|
    protocols.concat(Array(s.params['ssl_protocols']).flatten.map(&:to_s))
  end
  protocols = protocols.flat_map { |v| v.to_s.split }.uniq
  approved = %w[TLSv1.2 TLSv1.3]

  if protocols.empty?
    describe 'NGINX ssl_protocols directive' do
      skip 'not-applicable: no ssl_protocols directive in nginx.conf — TLS is likely terminated upstream.'
    end
  else
    offenders = protocols.reject { |p| approved.include?(p) }
    describe 'NGINX ssl_protocols outside the modern allowlist (TLSv1.2 / TLSv1.3)' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
