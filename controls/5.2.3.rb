# encoding: UTF-8

control 'C-5.2.3' do
  title 'Ensure the maximum buffer size for URIs is defined'
  desc  "
    The `large_client_header_buffers` directive allocates the maximum number and size of buffers for reading the entire client request header, which includes both the request line (e.g., `GET /path HTTP/1.1`) and all subsequent header fields (e.g., `Host:, Cookie:`, `Authorization:`). If a client's request header exceeds the total allocated buffer space, NGINX immediately rejects the request with a `400 Bad Request` error. Also, the client's request line cannot exceed the size of one buffer, otherwise the `414 Request-URI Too Large` error will be returned to the client.

    While NGINX itself is not vulnerable to buffer overflows from large headers, this directive serves two critical purposes:

    1. Denial of Service (DoS) Mitigation: It prevents malicious clients from attempting to exhaust server memory by sending excessively large headers.

    2. Downstream Protection: It acts as a gatekeeper, ensuring that malformed or oversized headers do not reach backend applications that might be more fragile or could exhibit undefined behavior when processing them.

    The default value is intentionally generous to handle legitimate modern web traffic, and lowering it without reason can be counterproductive.
  "
  desc  'rationale', "
    The `large_client_header_buffers` directive allocates the maximum number and size of buffers for reading the entire client request header, which includes both the request line (e.g., `GET /path HTTP/1.1`) and all subsequent header fields (e.g., `Host:, Cookie:`, `Authorization:`). If a client's request header exceeds the total allocated buffer space, NGINX immediately rejects the request with a `400 Bad Request` error. Also, the client's request line cannot exceed the size of one buffer, otherwise the `414 Request-URI Too Large` error will be returned to the client.

    While NGINX itself is not vulnerable to buffer overflows from large headers, this directive serves two critical purposes:

    1. Denial of Service (DoS) Mitigation: It prevents malicious clients from attempting to exhaust server memory by sending excessively large headers.

    2. Downstream Protection: It acts as a gatekeeper, ensuring that malformed or oversized headers do not reach backend applications that might be more fragile or could exhibit undefined behavior when processing them.

    The default value is intentionally generous to handle legitimate modern web traffic, and lowering it without reason can be counterproductive.
  "
  desc  'check', "
    This is a manual check that requires context.

    1. Run the following command to see if the directive is explicitly set:
    ```
    nginx -T 2>/dev/null | grep 'large_client_header_buffers'
    ```
    2. Evaluate the result:

    - No output: The server is using the default value of `4 8k`. This is considered compliant and secure for general use.
    - Output shows `large_client_header_buffers 4 8k;`: The default is explicitly set. This is compliant.
    - Output shows a different value (e.g., `2 1k;`): This is a deviation from the default. Manually verify if this restrictive value is documented, intentional, and necessary for the specific application. If not, it represents a potential availability risk and should be flagged.
  "
  desc  'fix', "
    Unless you have a specific, documented requirement to restrict header sizes further, the recommended action is to rely on the secure default value. If your configuration has an overly restrictive value set without a clear reason, remove the `large_client_header_buffers` directive from your `http` or `server` blocks to allow NGINX to fall back to its default.

    Remediation Action:

    Remove any custom, overly restrictive `large_client_header_buffers` lines from your configuration files.

    ```
    # REMOVE THIS LINE if it exists without good reason:
    large_client_header_buffers 2 1k;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.2.3'
  tag cis_rid:               '5.2.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050203r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  values = Array(nginx_http_values(nginx_conf(input('nginx_conf_path')), 'large_client_header_buffers')).flatten

  describe 'http.large_client_header_buffers — must be explicitly set' do
    subject { values }
    it { should_not be_empty }
  end
end
