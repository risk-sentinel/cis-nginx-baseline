# encoding: UTF-8

control 'C-4.1.8' do
  title 'Ensure HTTP Strict Transport Security (HSTS) is enabled'
  desc  "
    HTTP Strict Transport Security (HSTS) is a critical security header that instructs browsers to communicate with a domain exclusively over HTTPS. A comprehensive HSTS policy must include the `includeSubDomains` directive to apply the policy to all current and future subdomains. For maximum protection, the policy should also contain the `preload` directive, allowing the domain to be submitted to browser-pre-load lists. This ensures that even the very first connection to the domain is made securely. The `max-age` should be set to a long duration, typically two years (`63072000` seconds), to ensure browsers enforce this policy persistently.

    HSTS is the primary mechanism to mitigate protocol downgrade attacks and cookie hijacking. By enforcing HTTPS, it prevents attackers from intercepting requests and manipulating them. The `includeSubDomains` directive is vital as it closes a significant gap where an attacker could otherwise target a non-secure subdomain. The `preload` directive provides protection by removing the initial window of opportunity for an attack on a user's first visit, as the browser already knows to use HTTPS before making any connection.
  "
  desc  'rationale', "
    HTTP Strict Transport Security (HSTS) is a critical security header that instructs browsers to communicate with a domain exclusively over HTTPS. A comprehensive HSTS policy must include the `includeSubDomains` directive to apply the policy to all current and future subdomains. For maximum protection, the policy should also contain the `preload` directive, allowing the domain to be submitted to browser-pre-load lists. This ensures that even the very first connection to the domain is made securely. The `max-age` should be set to a long duration, typically two years (`63072000` seconds), to ensure browsers enforce this policy persistently.

    HSTS is the primary mechanism to mitigate protocol downgrade attacks and cookie hijacking. By enforcing HTTPS, it prevents attackers from intercepting requests and manipulating them. The `includeSubDomains` directive is vital as it closes a significant gap where an attacker could otherwise target a non-secure subdomain. The `preload` directive provides protection by removing the initial window of opportunity for an attack on a user's first visit, as the browser already knows to use HTTPS before making any connection.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for the `Strict-Transport-Security` header:
    ```
    nginx -T 2>/dev/null | grep -i 'Strict-Transport-Security'
    ```
    Verify that the output includes a header with the following components:

    - A `max-age` directive of at least `31536000` (one year), with `63072000` (two years) being the recommended value.
    - The `includeSubDomains` directive.
    - The `always` parameter at the end of the `add_header` directive.

    Example output:
    ```
    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;
    ```
  "
  desc  'fix', "
    It is critical to deploy HSTS incrementally to avoid locking users out.

    Step 1: Initial Rollout (Low `max-age`)

    Add the HSTS header with a very short `max-age` to test for any issues. Verify that all parts of your site, including all subdomains, function correctly over HTTPS.

    ```
    # Test with 5 minutes
    add_header Strict-Transport-Security \"max-age=300; includeSubDomains\" always;
    ```

    Step 2: Increase `max-age`

    Once confident, gradually increase the `max-age`.

    ```
    # Increase to 1 week
    add_header Strict-Transport-Security \"max-age=604800; includeSubDomains\" always;
    ```

    Step 3: Full Deployment (Long `max-age` and Preload)

    After thorough testing (e.g., one month), set the `max-age` to the recommended final value of two years. Add the `preload` directive if you intend to submit your site to the HSTS preload list.

    ```
    # Final configuration (2 years)
    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;
    ```
    If preloading is desired, submit your domain at [hstspreload.org](https://hstspreload.org).
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.8'
  tag cis_rid:               '4.1.8'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040108r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  conf = nginx_conf(input('nginx_conf_path'))
  add_headers = []
  add_headers.concat(Array(nginx_http_values(conf, 'add_header')).map { |args| Array(args).first.to_s })
  conf.http.servers.each do |s|
    add_headers.concat(Array(s.params['add_header']).map { |args| Array(args).first.to_s })
    s.locations.each do |l|
      add_headers.concat(Array(l.params['add_header']).map { |args| Array(args).first.to_s })
    end
  end

  describe 'NGINX add_header Strict-Transport-Security present (HSTS, CIS 4.1.8)' do
    subject { add_headers.any? { |h| h.casecmp('strict-transport-security').zero? } }
    it { should eq true }
  end
end
