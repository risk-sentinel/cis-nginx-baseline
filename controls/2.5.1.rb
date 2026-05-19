# encoding: UTF-8

control 'C-2.5.1' do
  title 'Ensure server_tokens directive is set to `off`'
  desc  "
    The `server_tokens` directive is responsible for displaying the NGINX version number and operating system version on error pages and in the `Server` `HTTP` response header field. This information should not be displayed.

    Attackers can conduct reconnaissance on a website using these response headers, then target attacks for specific known vulnerabilities associated with the underlying technologies. Hiding the version will slow down and deter some potential attackers.
  "
  desc  'rationale', "
    The `server_tokens` directive is responsible for displaying the NGINX version number and operating system version on error pages and in the `Server` `HTTP` response header field. This information should not be displayed.

    Attackers can conduct reconnaissance on a website using these response headers, then target attacks for specific known vulnerabilities associated with the underlying technologies. Hiding the version will slow down and deter some potential attackers.
  "
  desc  'check', "
    In the NGINX configuration file `nginx.conf`, verify the `server_tokens` directive is set to `off`. To do this, check the response headers for the server header by issuing this command:

    ```
    curl -I 127.0.0.1 | grep -i server
    ```

    The output should not contain the server header providing your server version, such as the below:

    ```
    Server: nginx/1.28.0
    ```
  "
  desc  'fix', "
    Disable version disclosure globally by adding the directive to the `http` block in `/etc/nginx/nginx.conf`:

    ```
    http {
        ...
        server_tokens        off;
        ...
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.5.1'
  tag cis_rid:               '2.5.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020501r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  value = Array(nginx_conf(input('nginx_conf_path')).http.params['server_tokens']).flatten.first
  describe 'http.server_tokens directive (CIS 2.5.1)' do
    subject { value }
    it { should eq 'off' }
  end
end
