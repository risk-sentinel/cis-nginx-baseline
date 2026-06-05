# encoding: UTF-8

control 'C-2.4.2' do
  title 'Ensure requests for unknown host names are rejected'
  desc  "
    NGINX routes incoming requests to the appropriate virtual host by matching the `Host` header (HTTP/1.1) or `:authority` pseudo-header (HTTP/2, HTTP/3) against the `server_name` directives in your configuration. If no explicit match is found, NGINX falls back to the first defined `server` block or the one marked as `default_server`. Without a properly configured catch-all block that rejects unknown hostnames, your server will respond to arbitrary domain names that happen to point to your IP address, potentially exposing internal applications or enabling Host Header attacks.

    When NGINX receives a request, it selects the virtual host based on the `Host` header (or `:authority` in HTTP/2/3). If requests for unknown host names are not explicitly rejected, your applications may be served for arbitrary domains that simply point to your IP. This behavior can be abused in Host Header attacks and makes it harder to distinguish legitimate traffic from automated scans or misrouted requests in your logs.
  "
  desc  'rationale', "
    NGINX routes incoming requests to the appropriate virtual host by matching the `Host` header (HTTP/1.1) or `:authority` pseudo-header (HTTP/2, HTTP/3) against the `server_name` directives in your configuration. If no explicit match is found, NGINX falls back to the first defined `server` block or the one marked as `default_server`. Without a properly configured catch-all block that rejects unknown hostnames, your server will respond to arbitrary domain names that happen to point to your IP address, potentially exposing internal applications or enabling Host Header attacks.

    When NGINX receives a request, it selects the virtual host based on the `Host` header (or `:authority` in HTTP/2/3). If requests for unknown host names are not explicitly rejected, your applications may be served for arbitrary domains that simply point to your IP. This behavior can be abused in Host Header attacks and makes it harder to distinguish legitimate traffic from automated scans or misrouted requests in your logs.
  "
  desc  'check', "
    1. Review Configuration:

    Check for the existence of a default `server` block that handles unknown hosts.
    ```
    nginx -T 2>/dev/null | grep -Ei \"listen.*default_server|ssl_reject_handshake\"
    ```
    Evaluation:

    - Ensure a `server` block exists with `listen ... default_server`.
    - Verify it contains `return 444;` (closes connection) or a `4xx` error code.
    - For HTTPS/TLS: Verify `ssl_reject_handshake on;` is used to prevent certificate leakage.

    2. Functional Test:

    Send a request with an invalid Host header and verify the connection is rejected or returns an error.

    ```
    # Test HTTPS (expect connection reset or 4xx)
    curl -k -v https://127.0.0.1 -H 'Host: invalid.example.com'
    ```
  "
  desc  'fix', "
    Configure a \"Catch-All\" default `server` block as the first block in your configuration (or explicitly marked with `default_server`).

    Configuration Example (Modern Standard with TLS/HTTP3):

    ```
    server {

        # Listen on standard ports for IPv4 and IPv6
        listen      80  default_server;
        listen [::]:80  default_server;

        # Listen for HTTPS (TCP) and QUIC (UDP)
        listen      443 ssl  default_server;
        listen [::]:443 ssl  default_server;
        listen      443 quic default_server;
        listen [::]:443 quic default_server;

        # Reject SSL Handshake for unknown domains (Prevents cert leakage)
        ssl_reject_handshake on;

        # Catch-all name
        server_name _;

        # Close connection without response (Non-standard code 444)
        return 444;

    }
    ```

    After adding this block, ensure all your valid applications have their own `server` blocks with explicit `server_name` directives.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '2.4.2'
  tag cis_rid:               '2.4.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020402r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  default_server_blocks = nginx_conf(input('nginx_conf_path')).http.servers.select do |server|
    Array(server.params['listen']).any? { |args| Array(args).join(' ').include?('default_server') }
  end

  if default_server_blocks.empty?
    describe 'NGINX default_server block handling unknown Host headers' do
      subject { default_server_blocks }
      it { should_not be_empty }
    end
  else
    offenders = default_server_blocks.reject do |server|
      returns = Array(server.params['return']).flatten.join(' ')
      returns =~ /\A\s*(444|404|410|421)/
    end
    describe 'NGINX default_server blocks not returning a rejecting status (444/404/410/421)' do
      subject { offenders.map { |s| Array(s.params['listen']).flatten.join(',') } }
      it { should be_empty }
    end
  end
end
