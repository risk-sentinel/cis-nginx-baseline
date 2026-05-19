# encoding: UTF-8

control 'C-5.2.1' do
  title 'Ensure timeout values for reading the client header and body are set correctly'
  desc  "
    To protect against slow clients holding connections open indefinitely, NGINX supports several timeout directives. The most important ones for client-facing connections are:

    - `client_header_timeout`: Sets the maximum time the server will wait for a client to send the request header.
    - `client_body_timeout`: Sets the maximum time allowed between sequential read operations when receiving the request body. This timer does not apply to the total time of the transfer.
    - `send_timeout`: Sets the maximum time allowed between sequential write operations when sending a response to the client.

    If any of these timeouts are reached, the server closes the connection, freeing up resources.

    Aggressively low timeout values are a primary defense against slow-read Denial of Service (DoS) attacks. These attacks attempt to exhaust server resources by opening many connections and keeping them alive for as long as possible by sending data extremely slowly. By setting low timeouts, NGINX efficiently closes these malicious connections, preserving resources for legitimate users.
  "
  desc  'rationale', "
    To protect against slow clients holding connections open indefinitely, NGINX supports several timeout directives. The most important ones for client-facing connections are:

    - `client_header_timeout`: Sets the maximum time the server will wait for a client to send the request header.
    - `client_body_timeout`: Sets the maximum time allowed between sequential read operations when receiving the request body. This timer does not apply to the total time of the transfer.
    - `send_timeout`: Sets the maximum time allowed between sequential write operations when sending a response to the client.

    If any of these timeouts are reached, the server closes the connection, freeing up resources.

    Aggressively low timeout values are a primary defense against slow-read Denial of Service (DoS) attacks. These attacks attempt to exhaust server resources by opening many connections and keeping them alive for as long as possible by sending data extremely slowly. By setting low timeouts, NGINX efficiently closes these malicious connections, preserving resources for legitimate users.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for the relevant directives:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(client_header_timeout|client_body_timeout|send_timeout)'
    ```
    Verify that these values are explicitly set to a reasonably low, non-default value (e.g., 10-20 seconds) in the main `http` or `server` context. If the application requires long-running connections, verify that `client_body_timeout` is overridden to a higher value in the specific `location` block that handles uploads.
  "
  desc  'fix', "
    Set reasonably low timeout values globally in your `http` block. If specific locations require longer timeouts (e.g., for file uploads), override them within that `location` block.

    Example Configuration:

    ```
    http {

        # Set a global default of 15 seconds, which overrides the default of 60s.

        client_header_timeout 15s;
        client_body_timeout   15s;
        send_timeout          15s;

        server {
            # ... other settings ...

            # This location handles large file uploads and needs a longer timeout.
            location /upload {

                client_body_timeout 300s; # Allow 5 minutes between read operations for uploads
                # ...
            }
        }
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.2.1'
  tag cis_rid:               '5.2.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050201r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  header_value = Array(conf.http.params['client_header_timeout']).flatten.first
  body_value   = Array(conf.http.params['client_body_timeout']).flatten.first

  describe 'http.client_header_timeout — must be set' do
    subject { header_value }
    it { should_not be_nil }
  end

  describe 'http.client_body_timeout — must be set' do
    subject { body_value }
    it { should_not be_nil }
  end

  if header_value
    seconds = header_value.to_s.gsub(/[^0-9]/, '').to_i
    describe 'http.client_header_timeout — 1..10 seconds (CIS 5.2.1)' do
      subject { seconds }
      it { should be > 0 }
      it { should be <= 10 }
    end
  end

  if body_value
    seconds = body_value.to_s.gsub(/[^0-9]/, '').to_i
    describe 'http.client_body_timeout — 1..10 seconds (CIS 5.2.1)' do
      subject { seconds }
      it { should be > 0 }
      it { should be <= 10 }
    end
  end
end
