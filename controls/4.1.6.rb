# encoding: UTF-8

control 'C-4.1.6' do
  title 'Ensure awareness of TLS 1.3 new Diffie-Hellman parameters'
  desc  "
    This control is not applicable to environments exclusively using TLS 1.3.

    The TLS 1.3 protocol (RFC 8446) deprecates the use of custom finite-field Diffie-Hellman (DHE) groups, which were configured via the `ssl_dhparam` directive in NGINX. Instead, TLS 1.3 exclusively uses a set of pre-defined, standardized, and secure elliptic curve (ECDHE) and finite-field (FFDHE) groups for its key exchange mechanism. This design eliminates the risk associated with weak or misconfigured custom DH parameters. As such, the `ssl_dhparam` directive has no effect in a TLS 1.3-only configuration.
  "
  desc  'rationale', "
    This control is not applicable to environments exclusively using TLS 1.3.

    The TLS 1.3 protocol (RFC 8446) deprecates the use of custom finite-field Diffie-Hellman (DHE) groups, which were configured via the `ssl_dhparam` directive in NGINX. Instead, TLS 1.3 exclusively uses a set of pre-defined, standardized, and secure elliptic curve (ECDHE) and finite-field (FFDHE) groups for its key exchange mechanism. This design eliminates the risk associated with weak or misconfigured custom DH parameters. As such, the `ssl_dhparam` directive has no effect in a TLS 1.3-only configuration.
  "
  desc  'check', "
    Verify that the configuration does not rely on TLS 1.2 or older protocols that would require this setting. This control is implicitly passed if control 4.1.4 (\"Ensure only modern TLS protocols are used\") is configured for TLS 1.3 exclusively.
  "
  desc  'fix', "
    No remediation is necessary. Ensure `ssl_protocols TLSv1.3;` is set. The `ssl_dhparam` directive should be removed as it is obsolete.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.6'
  tag cis_rid:               '4.1.6'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040106r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true


  conf = nginx_conf(input('nginx_conf_path'))
  protocols = Array(nginx_http_values(conf, 'ssl_protocols')).flatten.map(&:to_s)
  curves    = Array(nginx_http_values(conf, 'ssl_ecdh_curve')).flatten.map(&:to_s)
  conf.http.servers.each do |s|
    protocols.concat(Array(s.params['ssl_protocols']).flatten.map(&:to_s))
    curves.concat(Array(s.params['ssl_ecdh_curve']).flatten.map(&:to_s))
  end
  protocols = protocols.flat_map { |v| v.to_s.split }.uniq
  curves    = curves.flat_map { |v| v.to_s.split(/[:\s]+/) }.reject(&:empty?).uniq
  approved_curves = Array(input('nginx_approved_ecdh_curves')).map(&:to_s)

  termination = input('nginx_tls_termination')
  disp = tls_termination_disposition(termination, !(protocols.empty?))
  impact 0.0 if disp == :na

  if disp == :na
    describe 'NGINX TLS 1.3 negotiation parameters (4.1.6)' do
      skip "not-applicable: nginx_tls_termination=#{termination} — NGINX does not terminate TLS here; validate it at the terminating layer (the load balancer / compute / fargate ALB TLS controls)."
    end
  elsif disp == :missing
    describe 'NGINX must terminate TLS when nginx_tls_termination=nginx (4.1.6)' do
      subject { !(protocols.empty?) }
      it { is_expected.to be_truthy }
    end
  else
    describe 'NGINX TLS configuration (4.1.6)' do
      it 'offers TLS 1.3 (TLSv1.3 present in ssl_protocols)' do
        expect(protocols).to include('TLSv1.3')
      end
    end
    unless curves.empty? || approved_curves.empty?
      describe 'NGINX ssl_ecdh_curve groups outside the approved TLS 1.3 set' do
        subject { curves.reject { |c| c == 'auto' || approved_curves.include?(c) } }
        it { should be_empty }
      end
    end
  end
end
