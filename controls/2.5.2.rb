# encoding: UTF-8

control 'C-2.5.2' do
  title 'Ensure default error and index.html pages do not reference NGINX'
  desc  "
    Default error pages (e.g., `404`, `500`) and the default welcome page often contain NGINX branding or signatures. These pages should be removed or replaced with generic or custom-branded pages that do not disclose the underlying server technology.

    Standard NGINX error pages visually identify the server software, even if headers are suppressed. By gathering information about the underlying technology stack, attackers can tailor their exploits to known vulnerabilities of NGINX. Replacing default pages with generic or branded content removes this information leakage vector and increases the effort required for successful reconnaissance.
  "
  desc  'rationale', "
    Default error pages (e.g., `404`, `500`) and the default welcome page often contain NGINX branding or signatures. These pages should be removed or replaced with generic or custom-branded pages that do not disclose the underlying server technology.

    Standard NGINX error pages visually identify the server software, even if headers are suppressed. By gathering information about the underlying technology stack, attackers can tailor their exploits to known vulnerabilities of NGINX. Replacing default pages with generic or branded content removes this information leakage vector and increases the effort required for successful reconnaissance.
  "
  desc  'check', "
    1. Verify Config:

    Check if `error_page` directives are active:
    ```
    nginx -T 2>/dev/null | grep -i \"error_page\"
    ```
    2. Verify Content (Functional Test):

    Trigger an error (e.g., request a non-existent page) and inspect the body:
    ```
    curl -k https://127.0.0.1/non-existent-page | grep -i \"nginx\"
    ```
    Evaluation:

    - PASS: The output does not contain \"nginx\" (or `grep` returns nothing).
    - FAIL: The HTML body contains \"nginx\".
  "
  desc  'fix', "
    Instead of editing the default files (which may be overwritten by package updates), configure NGINX to use custom error pages.

    1. Create Custom Error Pages:

    Create a directory (e.g., `/var/www/html/errors`) and place generic HTML files there (e.g., `404.html`, `50x.html`) without NGINX branding.

    2. Configure NGINX:

    Add the `error_page` directive to your `http` or `server` blocks:

    ```
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;

    location = /50x.html {
        root /var/www/html/errors;
        internal;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.5.2'
  tag cis_rid:               '2.5.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020502r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  candidates = [
    '/usr/share/nginx/html/index.html',
    '/usr/share/nginx/html/50x.html',
    '/usr/share/nginx/html/404.html',
  ]
  offenders = candidates.select { |p| file(p).exist? && file(p).content.to_s.downcase.include?('nginx') }
  describe 'Default NGINX error / index pages referencing "nginx" literal' do
    subject { offenders }
    it { should be_empty }
  end
end
