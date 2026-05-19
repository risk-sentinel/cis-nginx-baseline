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
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip 'Requires manual review and attestation provided for this control (TLS 1.3 ECDHE / X25519 group selection is awareness-level only — NGINX picks suitable groups by default and the CIS check is informational, not actionable via a directive assertion)'
  end
end
