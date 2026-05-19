# encoding: UTF-8

control 'C-5.2.2' do
  title 'Ensure the maximum request body size is set correctly'
  desc  "
    The `client_max_body_size` directive defines the maximum permissible size for a client request body, as indicated by the `Content-Length` header. If a request exceeds this size, NGINX will immediately reject it with a `413 Request Entity Too Large` error, preventing the oversized request from being processed further or passed to a backend application.

    Limiting the request body size is a crucial defense against resource exhaustion DoS attacks and prevents oversized, potentially malicious payloads from reaching application backends. By setting a logical default limit and only increasing it for specific application endpoints that require it (e.g., file uploads), the principle of least functionality is enforced, significantly reducing the attack surface.
  "
  desc  'rationale', "
    The `client_max_body_size` directive defines the maximum permissible size for a client request body, as indicated by the `Content-Length` header. If a request exceeds this size, NGINX will immediately reject it with a `413 Request Entity Too Large` error, preventing the oversized request from being processed further or passed to a backend application.

    Limiting the request body size is a crucial defense against resource exhaustion DoS attacks and prevents oversized, potentially malicious payloads from reaching application backends. By setting a logical default limit and only increasing it for specific application endpoints that require it (e.g., file uploads), the principle of least functionality is enforced, significantly reducing the attack surface.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for the `client_max_body_size` directive:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(client_max_body_size)'
    ```
    Verify that a global `client_max_body_size` is set in the `http` block. For any location blocks that override this value (e.g., for uploads), manually verify that the increased limit is documented and aligns with the application's functional requirements.
  "
  desc  'fix', "
    Define a restrictive global limit in the `http` block. For specific application endpoints that need to accept larger request bodies, override this directive within the corresponding `location` block.

    Example Configuration:

    ```
    http {

        # Set a restrictive global default of 2 Megabytes. This prevents unexpected large requests on most endpoints.
        client_max_body_size 2M;

        server {
            # ...

            # This location handles API requests with potentially large JSON payloads.
            location /api/v1/data {
                client_max_body_size 10M; # Allow up to 10MB
                # ...
            }

            # This location is for large file uploads.
            location /uploads {
                client_max_body_size 50M; # Allow up to 50MB
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
  tag cis_number:            '5.2.2'
  tag cis_rid:               '5.2.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050202r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  values = Array(nginx_conf(input('nginx_conf_path')).http.params['client_max_body_size']).flatten

  describe 'http.client_max_body_size — must be explicitly set (not relying on default)' do
    subject { values }
    it { should_not be_empty }
  end
end
