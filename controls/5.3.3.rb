# encoding: UTF-8

control 'C-5.3.3' do
  title 'Ensure the Referrer Policy is enabled and configured properly'
  desc  "
    The `Referrer-Policy` HTTP header controls how much referrer information (sent via the `Referer` header) should be included with requests. It allows site administrators to restrict the data sent to upstream servers when a user clicks a link or loads a resource. This is a privacy control to prevent leaking sensitive URL parameters or internal path structures to third parties.

    URLs often contain sensitive information such as session tokens, search queries, or Personally Identifiable Information (PII) in their query parameters. Without a strict Referrer Policy, this full URL is transmitted to any third-party site the user visits from your page, potentially logging sensitive data on external servers. Configuring this header ensures that only the necessary information (e.g., just the origin domain) is shared, protecting user privacy and preventing data leakage.
  "
  desc  'rationale', "
    The `Referrer-Policy` HTTP header controls how much referrer information (sent via the `Referer` header) should be included with requests. It allows site administrators to restrict the data sent to upstream servers when a user clicks a link or loads a resource. This is a privacy control to prevent leaking sensitive URL parameters or internal path structures to third parties.

    URLs often contain sensitive information such as session tokens, search queries, or Personally Identifiable Information (PII) in their query parameters. Without a strict Referrer Policy, this full URL is transmitted to any third-party site the user visits from your page, potentially logging sensitive data on external servers. Configuring this header ensures that only the necessary information (e.g., just the origin domain) is shared, protecting user privacy and preventing data leakage.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration:
    ```
    nginx -T 2>/dev/null | grep -i 'Referrer-Policy'
    ```
    Evaluate the findings:

    - Verify that the directive `add_header Referrer-Policy \"...\" always;` is present.
    - Check the configured value. While `no-referrer` is the most secure, `strict-origin-when-cross-origin` is the widely accepted standard for balancing security and functionality.
    - Ensure the `always` parameter is present.
  "
  desc  'fix', "
    Add the following line to your `server` or `http` block. This example uses the robust default setting that protects privacy without breaking internal analytics.
    ```
    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;
    ```
    If maximum privacy is required and no referrer data is needed even for internal links:
    ```
    add_header Referrer-Policy \"no-referrer\" always;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.3.3'
  tag cis_rid:               '5.3.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050303r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  values = []
  check_params = lambda do |params|
    Array(params['add_header']).each do |args|
      tokens = Array(args).map(&:to_s)
      values << tokens[1].to_s.gsub(/["';]/, '').strip if tokens[0]&.casecmp?('Referrer-Policy')
    end
  end
  check_params.call(conf.http.params)
  conf.http.servers.each do |s|
    check_params.call(s.params)
    s.locations.each { |l| check_params.call(l.params) }
  end

  acceptable = %w[no-referrer no-referrer-when-downgrade strict-origin strict-origin-when-cross-origin same-origin]

  describe 'NGINX add_header Referrer-Policy present with a strict value (CIS 5.3.3)' do
    subject { values.any? { |v| acceptable.include?(v) } }
    it { should eq true }
  end
end
