# encoding: UTF-8

control 'C-2.4.3' do
  title 'Ensure keepalive_timeout is 10 seconds or less, but not 0'
  desc  "
    Persistent connections are leveraged by all modern browsers to facilitate greater web performance. The keep-alive timeout limits the time a persistent connection may remain open. Setting the keep-alive timeout allows this timeout to be controlled on the server side.

    Setting a keep-alive timeout on the server side helps mitigate denial of service attacks that establish too many persistent connections, exhausting server resources.
  "
  desc  'rationale', "
    Persistent connections are leveraged by all modern browsers to facilitate greater web performance. The keep-alive timeout limits the time a persistent connection may remain open. Setting the keep-alive timeout allows this timeout to be controlled on the server side.

    Setting a keep-alive timeout on the server side helps mitigate denial of service attacks that establish too many persistent connections, exhausting server resources.
  "
  desc  'check', "
    To check the current setting for the `keepalive_timeout` directive, issue the below command. You should also manually check your nginx configuration for include statements that may be located outside the `/etc/nginx` directory. If none of these are present, the value is set at the default.

    ```
    grep -ir keepalive_timeout /etc/nginx
    ```

    The output of the command should contain something similar to the following:

    ```
    keepalive_timeout 10;
    ```
  "
  desc  'fix', "
    Find the `HTTP` or server block of your nginx configuration, and add the `keepalive_timeout` directive. Set it to `10` seconds or less, but not `0`. This example command sets it to `10` seconds:

    ```
    keepalive_timeout 10;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.4.3'
  tag cis_rid:               '2.4.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020403r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  value = Array(nginx_http_values(nginx_conf(input('nginx_conf_path')), 'keepalive_timeout')).flatten.first

  describe 'http.keepalive_timeout directive — must be present' do
    subject { value }
    it { should_not be_nil }
  end

  if value
    seconds = value.to_s.gsub(/[^0-9]/, '').to_i
    describe 'http.keepalive_timeout numeric value — 1..10 seconds (CIS 2.4.3)' do
      subject { seconds }
      it { should be > 0 }
      it { should be <= 10 }
    end
  end
end
