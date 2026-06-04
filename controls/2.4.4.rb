# encoding: UTF-8

control 'C-2.4.4' do
  title 'Ensure send_timeout is set to 10 seconds or less, but not 0'
  desc  "
    The `send_timeout` directive sets a timeout for transmitting a response to the client between two successive write operations.

    Setting the `send_timeout` directive on the server side helps mitigate slow `HTTP` denial of service attacks by ensuring write operations taking up large amounts of time are closed.
  "
  desc  'rationale', "
    The `send_timeout` directive sets a timeout for transmitting a response to the client between two successive write operations.

    Setting the `send_timeout` directive on the server side helps mitigate slow `HTTP` denial of service attacks by ensuring write operations taking up large amounts of time are closed.
  "
  desc  'check', "
    To check the current setting for the `send_timeout` directive, issue the below command. You should also manually check your nginx configuration for include statements that may be located outside the `/etc/nginx` directory. If none of these are present, the value is set at the default.

    ```
    grep -ir send_timeout /etc/nginx
    ```

    The output of the command should be similar to the following:

    ```
    send_timeout  10;
    ```
  "
  desc  'fix', "
    Find the `HTTP` or server block of your nginx configuration, and add the `send_timeout` directive. Set it to `10` seconds or less, but not `0`.

    ```
    send_timeout   10;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.4.4'
  tag cis_rid:               '2.4.4'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020404r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  value = Array(nginx_http_values(nginx_conf(input('nginx_conf_path')), 'send_timeout')).flatten.first

  describe 'http.send_timeout directive — must be present' do
    subject { value }
    it { should_not be_nil }
  end

  if value
    seconds = value.to_s.gsub(/[^0-9]/, '').to_i
    describe 'http.send_timeout numeric value — 1..10 seconds (CIS 2.4.4)' do
      subject { seconds }
      it { should be > 0 }
      it { should be <= 10 }
    end
  end
end
