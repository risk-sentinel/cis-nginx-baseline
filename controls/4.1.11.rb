# encoding: UTF-8

control 'C-4.1.11' do
  title 'Ensure Secure Session Resumption is Enabled'
  desc  "
    TLS 1.3 introduces a secure session resumption mechanism using Pre-Shared Keys (PSKs) that significantly improves performance for returning clients by reducing the handshake latency. This modern mechanism should be enabled to enhance user experience without compromising security.

    Unlike older TLS versions, the TLS 1.3 resumption mechanism preserves Perfect Forward Secrecy (PFS). It accomplishes this by combining the PSK with a fresh Ephemeral Diffie-Hellman key exchange (ECDHE) for every resumed session. This ensures that a compromise of the resumption key does not compromise any past or future session keys. Disabling this feature provides no security benefit and negatively impacts performance.
  "
  desc  'rationale', "
    TLS 1.3 introduces a secure session resumption mechanism using Pre-Shared Keys (PSKs) that significantly improves performance for returning clients by reducing the handshake latency. This modern mechanism should be enabled to enhance user experience without compromising security.

    Unlike older TLS versions, the TLS 1.3 resumption mechanism preserves Perfect Forward Secrecy (PFS). It accomplishes this by combining the PSK with a fresh Ephemeral Diffie-Hellman key exchange (ECDHE) for every resumed session. This ensures that a compromise of the resumption key does not compromise any past or future session keys. Disabling this feature provides no security benefit and negatively impacts performance.
  "
  desc  'check', "
    Run the following command to verify that `ssl_session_tickets` is not explicitly turned `off`.

    ```
    # This command should produce NO output.
    grep -ir \"ssl_session_tickets\" /etc/nginx/ | grep -i \"off\"
    ```

    If the command produces any output containing `ssl_session_tickets off;`, this recommendation is not implemented.
  "
  desc  'fix', "
    Ensure that `ssl_session_tickets` is not set to `off`. The recommended approach is to remove the directive entirely, as the default value is `on`.

    If the directive is present, either remove it or set it to `on`:

    ```
    # REMOVE this line from your configuration:
    # ssl_session_tickets off;

    # OR, if you want to be explicit, ensure it is set to ON (optional):
    ssl_session_tickets  on;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.11'
  tag cis_rid:               '4.1.11'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040111r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  has_tls = !Array(conf.http.params['ssl_certificate']).empty? ||
            conf.http.servers.any? { |s| !Array(s.params['ssl_certificate']).empty? }

  if !has_tls
    describe 'NGINX TLS session resumption' do
      skip 'not-applicable: no ssl_certificate directives — TLS is terminated upstream.'
    end
  else
    cache_values = Array(conf.http.params['ssl_session_cache']).flatten.map(&:to_s)
    timeout_values = Array(conf.http.params['ssl_session_timeout']).flatten.map(&:to_s)
    tickets_values = Array(conf.http.params['ssl_session_tickets']).flatten.map(&:to_s)

    describe 'NGINX ssl_session_cache configured (shared) for TLS session resumption (CIS 4.1.11)' do
      subject { cache_values.any? { |v| v.start_with?('shared:') } }
      it { should eq true }
    end

    describe 'NGINX ssl_session_timeout set' do
      subject { timeout_values }
      it { should_not be_empty }
    end

    if tickets_values.any?
      describe 'NGINX ssl_session_tickets set to off (preferred — uses ssl_session_cache)' do
        subject { tickets_values }
        it { should all(eq 'off') }
      end
    end
  end
end
