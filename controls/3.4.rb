# encoding: UTF-8

control 'C-3.4' do
  title 'Ensure proxies pass source IP information'
  desc  "
    When NGINX acts as a reverse proxy or load balancer, it terminates the client connection and opens a new connection to the upstream application server. By default, the upstream server sees the NGINX server's internal IP address as the source, obscuring the original client IP. Standard HTTP headers like `X-Forwarded-For` and `X-Real-IP` must be explicitly configured to pass the original client's IP address and protocol information to the backend application.

    Visibility of the true client IP address is essential for security auditing, incident response, and access control within the backend application. Without forwarding this information:

    1. Forensics: Application logs will show all traffic coming from the NGINX proxy IP, making it impossible to trace malicious activity to a specific attacker.
    2. Access Control: Application-level IP allow/deny lists or rate limits will fail or mistakenly block the entire proxy.
    3. Compliance: Accurate logging of the user origin is often a regulatory requirement.
  "
  desc  'rationale', "
    When NGINX acts as a reverse proxy or load balancer, it terminates the client connection and opens a new connection to the upstream application server. By default, the upstream server sees the NGINX server's internal IP address as the source, obscuring the original client IP. Standard HTTP headers like `X-Forwarded-For` and `X-Real-IP` must be explicitly configured to pass the original client's IP address and protocol information to the backend application.

    Visibility of the true client IP address is essential for security auditing, incident response, and access control within the backend application. Without forwarding this information:

    1. Forensics: Application logs will show all traffic coming from the NGINX proxy IP, making it impossible to trace malicious activity to a specific attacker.
    2. Access Control: Application-level IP allow/deny lists or rate limits will fail or mistakenly block the entire proxy.
    3. Compliance: Accurate logging of the user origin is often a regulatory requirement.
  "
  desc  'check', "
    1. Verify Configuration:

    Check the active configuration for proxy header directives in proxied locations:
    ```
    nginx -T 2>/dev/null | grep -E \"proxy_set_header (X-Real-IP|X-Forwarded-For)\"
    ```
    Evaluation:

    - Presence: Verify that `proxy_set_header X-Forwarded-For` and `proxy_set_header X-Real-IP` are present in `location` blocks that use `proxy_pass` (or `grpc_pass`, `fastcgi_pass`).

    - Correctness:

      - `X-Forwarded-For` should typically use `$proxy_add_x_forwarded_for` (to preserve the chain) or `$remote_addr` (if NGINX is the first trusted hop).

      - `X-Real-IP` should use `$remote_addr`.

    - Scope: Check that this is applied to all relevant proxied locations.
  "
  desc  'fix', "
    Configure NGINX to forward client IP information in your `server` or `location` blocks where `proxy_pass` is used.

    Configuration Example:
    ```
    location / {

        # Use 'https' for Zero Trust environments (requires proxy_ssl_verify configuration)
        # Use 'http'  for standard TLS offloading (upstream traffic is unencrypted)
        proxy_pass ://example_backend_application;

        # Standard header: Appends the client IP to the list of proxies
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;

        # NGINX-specific header: Sets the direct client IP (useful for apps expecting a single value)
        proxy_set_header X-Real-IP         $remote_addr;

        # Recommended: Forward the protocol (http vs https)
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AU-3 d']
  tag cci:                   ['CCI-001682', 'CCI-000133']
  tag cis_number:            '3.4'
  tag cis_rid:               '3.4'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-0304r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  proxy_pass_locations = conf.http.servers.flat_map(&:locations).select { |l| !Array(l.params['proxy_pass']).empty? }

  if proxy_pass_locations.empty?
    describe 'NGINX proxy headers for source IP propagation' do
      skip 'not-applicable: no proxy_pass directives detected — NGINX is not acting as a reverse proxy on this target.'
    end
  else
    required_headers = %w[X-Real-IP X-Forwarded-For X-Forwarded-Proto X-Forwarded-Host]
    offenders = proxy_pass_locations.each_with_object([]) do |loc, acc|
      set_headers = Array(loc.params['proxy_set_header']).map { |args| Array(args).first.to_s }
      # Also consider headers set at the http or server level (inherited).
      inherited_http = Array(conf.http.params['proxy_set_header']).map { |args| Array(args).first.to_s }
      inherited_server = loc.parent.respond_to?(:params) ? Array(loc.parent.params['proxy_set_header']).map { |args| Array(args).first.to_s } : []
      effective = (set_headers + inherited_http + inherited_server).uniq
      missing = required_headers - effective
      acc << "location=#{loc.params['_'].inspect}:missing=#{missing.join(',')}" unless missing.empty?
    end

    describe 'NGINX proxy_pass locations missing source-IP propagation headers' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
