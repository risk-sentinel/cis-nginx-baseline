# encoding: UTF-8

control 'C-5.3.2' do
  title 'Ensure that Content Security Policy (CSP) is enabled and configured properly'
  desc  "
    Content Security Policy (CSP) is an HTTP response header that allows site administrators to declare approved sources of content that browsers are allowed to load on that page. It is a mechanism to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. Furthermore, CSP's `frame-ancestors` directive is the modern replacement for the `X-Frame-Options` header to prevent Clickjacking.

    A robust CSP significantly reduces the attack surface of a web application. By restricting the domains from which scripts, styles, images, and other resources can be loaded, it effectively neutralizes many XSS vectors. Additionally, by using the `frame-ancestors` directive, it explicitly controls which parent pages are allowed to embed the application (e.g., via ` `), providing a more flexible protection against Clickjacking than the legacy `X-Frame-Options` header.
  "
  desc  'rationale', "
    Content Security Policy (CSP) is an HTTP response header that allows site administrators to declare approved sources of content that browsers are allowed to load on that page. It is a mechanism to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. Furthermore, CSP's `frame-ancestors` directive is the modern replacement for the `X-Frame-Options` header to prevent Clickjacking.

    A robust CSP significantly reduces the attack surface of a web application. By restricting the domains from which scripts, styles, images, and other resources can be loaded, it effectively neutralizes many XSS vectors. Additionally, by using the `frame-ancestors` directive, it explicitly controls which parent pages are allowed to embed the application (e.g., via ` `), providing a more flexible protection against Clickjacking than the legacy `X-Frame-Options` header.
  "
  desc  'check', "
    1. Run the following command to inspect the CSP configuration:
    ```
    nginx -T 2>/dev/null | grep -i 'Content-Security-Policy'
    ```
    2. Evaluate the policy:

    - Is the header present?
    - Does it include at least a restrictive `default-src` directive (e.g., '`self`' or '`none`')?
    - Does it include the `frame-ancestors` directive to mitigate Clickjacking?
    - Critically: Is `unsafe-inline` or `unsafe-eval` avoided in `script-src`? (Allowing these significantly weakens the protection).
  "
  desc  'fix', "
    CSP must be tailored to the specific application. There is no single \"correct\" policy.

    Step 1: The Baseline Policy (High Security)

    Start with a policy that denies everything by default and only allows resources from the same origin. It also prevents the site from being framed by anyone (Clickjacking protection).
    ```
    add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'; form-action 'self';\" always;
    ```

    Step 2: Adaptation (Example)

    If your application loads images from a CDN and needs to be embeddable by a specific partner site:
    ```
    add_header Content-Security-Policy \"default-src 'self'; img-src 'self' https://cdn.example.com; frame-ancestors 'self' https://partner-site.com;\" always;
    ```
    Note: Use `Content-Security-Policy-Report-Only` during the testing phase to debug your policy without breaking the site.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-7 a']
  tag cci:                   ['CCI-002704']
  tag cis_number:            '5.3.2'
  tag cis_rid:               '5.3.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050302r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  csp_present = false
  check_params = lambda do |params|
    Array(params['add_header']).each do |args|
      tokens = Array(args).map(&:to_s)
      csp_present = true if tokens[0]&.casecmp?('Content-Security-Policy')
    end
  end
  check_params.call((Array(conf.params['http']).first || {}))
  conf.http.servers.each do |s|
    check_params.call(s.params)
    s.locations.each { |l| check_params.call(l.params) }
  end

  describe 'NGINX add_header Content-Security-Policy present (CIS 5.3.2)' do
    subject { csp_present }
    it { should eq true }
  end
end
