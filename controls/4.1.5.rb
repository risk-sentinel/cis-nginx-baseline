# encoding: UTF-8

control 'C-4.1.5' do
  title 'Disable weak ciphers'
  desc  "
    The `ssl_protocols` directive must be used to disable weak protocols and exclusively enable TLS 1.3. In a TLS 1.3-only configuration, the `ssl_ciphers` directive is no longer necessary, as the protocol itself mandates a small, non-negotiable set of highly secure AEAD ciphers (Authenticated Encryption with Associated Data). This approach simplifies configuration and eliminates the risk of choosing weak or insecure cipher suites.

    The `ssl_prefer_server_ciphers` directive should be set to off for TLS 1.3. Since all available ciphers are secure, allowing the client (user agent) to choose the most performant cipher for its hardware provides a performance benefit without compromising security.

    In a reverse proxy setup, it is critical to ensure that any upstream services also support TLS 1.3. If an upstream server requires an older protocol, the `proxy_ssl_protocols` and `proxy_ssl_ciphers` directives must be configured to match the upstream's requirements, but this should be treated as a temporary exception to be remediated.

    Weak cryptographic ciphers can lead to the compromise of sensitive data. In modern TLS configurations, the most effective way to disable all weak ciphers is to exclusively enable the TLS 1.3 protocol. The TLS 1.3 specification removes all previously known weak and legacy cipher suites, mandating the use of a small set of highly secure Authenticated Encryption (AEAD) ciphers. This approach is simpler and less error-prone than maintaining a complex denylist or allowlist of ciphers for older protocols.
  "
  desc  'rationale', "
    The `ssl_protocols` directive must be used to disable weak protocols and exclusively enable TLS 1.3. In a TLS 1.3-only configuration, the `ssl_ciphers` directive is no longer necessary, as the protocol itself mandates a small, non-negotiable set of highly secure AEAD ciphers (Authenticated Encryption with Associated Data). This approach simplifies configuration and eliminates the risk of choosing weak or insecure cipher suites.

    The `ssl_prefer_server_ciphers` directive should be set to off for TLS 1.3. Since all available ciphers are secure, allowing the client (user agent) to choose the most performant cipher for its hardware provides a performance benefit without compromising security.

    In a reverse proxy setup, it is critical to ensure that any upstream services also support TLS 1.3. If an upstream server requires an older protocol, the `proxy_ssl_protocols` and `proxy_ssl_ciphers` directives must be configured to match the upstream's requirements, but this should be treated as a temporary exception to be remediated.

    Weak cryptographic ciphers can lead to the compromise of sensitive data. In modern TLS configurations, the most effective way to disable all weak ciphers is to exclusively enable the TLS 1.3 protocol. The TLS 1.3 specification removes all previously known weak and legacy cipher suites, mandating the use of a small set of highly secure Authenticated Encryption (AEAD) ciphers. This approach is simpler and less error-prone than maintaining a complex denylist or allowlist of ciphers for older protocols.
  "
  desc  'check', "
    Use the following procedure to verify that only `ssl_protocols TLSv1.3;` is used.

    ```
    nginx -T 2>/dev/null | grep -E '^\\s*ssl_protocols'
    ```

    The output must show `ssl_protocols TLSv1.3;` exclusively for every relevant configuration block (e.g., at the `http` or `server` level).﻿

    Example output:
    ```
    nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
    nginx: configuration file /etc/nginx/nginx.conf test is successful
    # configuration file /etc/nginx/nginx.conf:
            ssl_protocols TLSv1.3;
    # configuration file /etc/nginx/conf.d/default.conf:
            ssl_protocols TLSv1.3;
    ```
  "
  desc  'fix', "
    Set `ssl_protocols TLSv1.3;`. The `ssl_ciphers` directive is not required for a TLS 1.3-only configuration, as the secure defaults of the underlying crypto library (e.g., OpenSSL) will be used.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.5'
  tag cis_rid:               '4.1.5'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040105r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  conf = nginx_conf(input('nginx_conf_path'))
  cipher_strings = Array(nginx_http_values(conf, 'ssl_ciphers')).flatten.map(&:to_s)
  conf.http.servers.each do |s|
    cipher_strings.concat(Array(s.params['ssl_ciphers']).flatten.map(&:to_s))
  end
  weak_patterns = /(NULL|EXPORT|DES|MD5|RC4|3DES|aNULL|eNULL|LOW|PSK)/i

  termination = input('nginx_tls_termination')
  disp = tls_termination_disposition(termination, !(cipher_strings.empty?))
  impact 0.0 if disp == :na

  if disp == :na
    describe 'NGINX ssl_ciphers directive' do
      skip "not-applicable: nginx_tls_termination=#{termination} — NGINX does not terminate TLS here; validate it at the terminating layer (the load balancer / compute / fargate ALB TLS controls)."
    end
  elsif disp == :missing
    describe 'NGINX must terminate TLS when nginx_tls_termination=nginx (4.1.5)' do
      subject { !(cipher_strings.empty?) }
      it { is_expected.to be_truthy }
    end
  else
    offenders = cipher_strings.select { |c| c =~ weak_patterns }
    describe 'NGINX ssl_ciphers strings containing weak/disallowed primitives (NULL/EXPORT/DES/MD5/RC4/3DES/aNULL/eNULL/LOW/PSK)' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
