# encoding: UTF-8

control 'C-5.3.1' do
  title 'Ensure X-Content-Type-Options header is configured and enabled'
  desc  "
    The `X-Content-Type-Options` header instructs the browser to strictly follow the MIME types declared in the `Content-Type` headers and not to guess (\"sniff\") the content type based on the file's actual content.

    Implementing the `X-Content-Type-Options` header with the `nosniff` directive helps to prevent drive-by download attacks where a user agent is sniffing content types in responses.

    This header prevents \"MIME type confusion\" attacks. Without this header, browsers might interpret a file declared as text (e.g., `snippet.txt`) as executable if it contains script code. Setting the `nosniff` directive forces the browser to reject the file if the declared type doesn't match the context in which it's loaded (e.g., loading a text file as a script).
  "
  desc  'rationale', "
    The `X-Content-Type-Options` header instructs the browser to strictly follow the MIME types declared in the `Content-Type` headers and not to guess (\"sniff\") the content type based on the file's actual content.

    Implementing the `X-Content-Type-Options` header with the `nosniff` directive helps to prevent drive-by download attacks where a user agent is sniffing content types in responses.

    This header prevents \"MIME type confusion\" attacks. Without this header, browsers might interpret a file declared as text (e.g., `snippet.txt`) as executable if it contains script code. Setting the `nosniff` directive forces the browser to reject the file if the declared type doesn't match the context in which it's loaded (e.g., loading a text file as a script).
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration:
    ```
    nginx -T 2>/dev/null | grep -i 'X-Content-Type-Options'
    ```
    Verify the output:

    - Verify that the configuration contains the line: `add_header X-Content-Type-Options \"nosniff\" always;`
    - Specifically check for the `always` parameter at the end of the directive. Without it, the header will be missing on error pages.
  "
  desc  'fix', "
    Open the NGINX configuration file that contains your `server` blocks. Add the below line into your `server` block to `add X-Content-Type-Options` header and direct your user agent to not sniff content types.

    ```
    add_header X-Content-Type-Options \"nosniff\" always;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.3.1'
  tag cis_rid:               '5.3.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050301r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  matching = []
  collect_add_headers = lambda do |params|
    Array(params['add_header']).each do |args|
      tokens = Array(args).map(&:to_s)
      next unless tokens[0]&.casecmp?('X-Content-Type-Options')
      matching << tokens[1].to_s
    end
  end
  collect_add_headers.call(conf.http.params)
  conf.http.servers.each do |s|
    collect_add_headers.call(s.params)
    s.locations.each { |l| collect_add_headers.call(l.params) }
  end

  describe 'NGINX add_header X-Content-Type-Options "nosniff" (CIS 5.3.1)' do
    subject { matching.any? { |v| v.gsub(/["';]/, '').casecmp('nosniff').zero? } }
    it { should eq true }
  end
end
