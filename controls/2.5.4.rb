# encoding: UTF-8

control 'C-2.5.4' do
  title 'Ensure the NGINX reverse proxy does not enable information disclosure'
  desc  "
    When NGINX acts as a reverse proxy, it forwards headers sent by the upstream application (e.g., \"`X-Powered-By: Custom_APP`\" or \"`Server: Apache/2.4`\"). These headers should be stripped before the response reaches the client to prevent information disclosure about the backend infrastructure.

    Attackers conduct reconnaissance by inspecting response headers to identify the technologies used in the backend (e.g., specific versions of PHP, Java/Tomcat, or Python frameworks). Knowing the exact version allows attackers to target specific CVEs associated with that software stack. Removing these headers reduces the information available for targeted attacks.
  "
  desc  'rationale', "
    When NGINX acts as a reverse proxy, it forwards headers sent by the upstream application (e.g., \"`X-Powered-By: Custom_APP`\" or \"`Server: Apache/2.4`\"). These headers should be stripped before the response reaches the client to prevent information disclosure about the backend infrastructure.

    Attackers conduct reconnaissance by inspecting response headers to identify the technologies used in the backend (e.g., specific versions of PHP, Java/Tomcat, or Python frameworks). Knowing the exact version allows attackers to target specific CVEs associated with that software stack. Removing these headers reduces the information available for targeted attacks.
  "
  desc  'check', "
    1. Configuration Check:

    Search the loaded configuration for header hiding directives:
    ```
    nginx -T 2>/dev/null | grep -Ei \"(proxy|fastcgi)_hide_header\"
    ```
    Evaluation:

    - Verify that directives exist to hide `X-Powered-By` and `Server`.

    2. Functional Check (Recommended):

    Send a request to a proxied endpoint and inspect the response headers:
    ```
    curl -k -I https://127.0.0.1 | grep -Ei \"^(Server|X-Powered-By)\"
    ```
    Evaluation:

    - PASS: The output does not contain backend details (e.g., `X-Powered-By: PHP/8.2`). If Server is present, it should only be `Server: nginx` (controlled by Control 2.5.1).
    - FAIL: The output contains backend information or unmasked version numbers.
  "
  desc  'fix', "
    Configure NGINX to strip the sensitive headers. The directive depends on the upstream protocol (HTTP Proxy vs. FastCGI).

    For Standard Reverse Proxy (`proxy_pass`):

    Add the following directives to your `http`, `server`, or `location` block:

    ```
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;
    ```


    For PHP/FastCGI (`fastcgi_pass`):

    If you are using FastCGI (e.g., for PHP-FPM), use the `fastcgi_hide_header` directive instead:
    ```
    fastcgi_hide_header X-Powered-By;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.5.4'
  tag cis_rid:               '2.5.4'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020504r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  has_proxy_pass = !Array(conf.http.params['proxy_pass']).empty? ||
                   conf.http.servers.flat_map(&:locations).any? { |l| !Array(l.params['proxy_pass']).empty? }

  if !has_proxy_pass
    describe 'NGINX reverse-proxy info-disclosure hardening' do
      skip 'not-applicable: no proxy_pass directives detected anywhere in nginx.conf — NGINX is not acting as a reverse proxy on this target.'
    end
  else
    required_hidden = %w[X-Powered-By Server X-AspNet-Version X-AspNetMvc-Version]
    hidden = Array(conf.http.params['proxy_hide_header']).map { |args| Array(args).first.to_s }
    missing = required_hidden - hidden
    describe 'NGINX proxy_hide_header missing info-disclosure-shielding entries' do
      subject { missing }
      it { should be_empty }
    end
  end
end
