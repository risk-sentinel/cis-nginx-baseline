# encoding: UTF-8

control 'C-4.1.12' do
  title 'Ensure HTTP/3.0 is used'
  desc  "
    HTTP/2 is the established standard for web communication, offering significant performance benefits over HTTP/1.1 through multiplexing. For 2025 and beyond, HTTP/3 should also be enabled. HTTP/3 operates over the QUIC protocol, which is built on UDP, to solve head-of-line blocking, reduce connection setup time, and improve performance on unreliable networks. Both protocols require a secure TLS 1.3 environment to function.

    Enabling HTTP/2 provides a baseline of modern performance via stream multiplexing. Enabling HTTP/3 provides a further competitive advantage by mitigating TCP's head-of-line blocking and offering a faster, more reliable connection handshake, which is especially beneficial for mobile users. A server supporting both protocols can serve the vast majority of modern clients with the best possible performance and security. The strong encryption requirements of both protocols naturally align with a TLS 1.3-only policy.
  "
  desc  'rationale', "
    HTTP/2 is the established standard for web communication, offering significant performance benefits over HTTP/1.1 through multiplexing. For 2025 and beyond, HTTP/3 should also be enabled. HTTP/3 operates over the QUIC protocol, which is built on UDP, to solve head-of-line blocking, reduce connection setup time, and improve performance on unreliable networks. Both protocols require a secure TLS 1.3 environment to function.

    Enabling HTTP/2 provides a baseline of modern performance via stream multiplexing. Enabling HTTP/3 provides a further competitive advantage by mitigating TCP's head-of-line blocking and offering a faster, more reliable connection handshake, which is especially beneficial for mobile users. A server supporting both protocols can serve the vast majority of modern clients with the best possible performance and security. The strong encryption requirements of both protocols naturally align with a TLS 1.3-only policy.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(listen|add_header.*Alt-Svc)'
    ```
    Verify the following in the output for your primary `server` block:

    1. The TCP `listen` directive includes the `http2` parameter: `listen 443 ssl http2;`

    2. A UDP `listen` directive with the `quic` parameter exists: `listen 443 quic reuseport;`

    3. An `Alt-Svc` header is being sent to advertise HTTP/3 availability: `add_header Alt-Svc 'h3=\":443\"; ma=63072000';`

    If any of these are missing, this recommendation is not fully implemented.
  "
  desc  'fix', "
    Prerequisite:
    Ensure your NGINX version is compiled with the` --with-http_v3_module` flag.

    1. Open your NGINX server configuration file.
    2. In the main `server` block for your HTTPS site, add or modify the directives to enable HTTP/2, HTTP/3, and advertise its availability.
    3. Ensure your firewall allows UDP traffic on port `443`.

    ```
    server {
        # 1. Enable HTTP/2 on the standard TCP listener
        listen         443      ssl http2;
        listen         [::]:443 ssl http2;

        # 2. Enable HTTP/3 on the UDP listener
        listen         443      quic reuseport;
        listen         [::]:443 quic reuseport;

        # ... other ssl directives like ssl_certificate ...

        # 3. Advertise HTTP/3 availability to browsers
        # The max-age (ma) is in seconds (e.g., 2 years)
        add_header      Alt-Svc 'h3=\":443\"; ma=63072000';

        # Required for HTTP/3
        ssl_early_data  on;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.12'
  tag cis_rid:               '4.1.12'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040112r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip 'Requires manual review and attestation provided for this control (HTTP/3 / QUIC adoption is an enablement target rather than a CIS-style hard requirement — many production deployments intentionally stay on HTTP/2 until the QUIC stack matures across their middleboxes; operators attest the choice from their architecture record)'
  end
end
