# encoding: UTF-8

control 'C-4.1.9' do
  title 'Ensure upstream server traffic is authenticated with a client certificate'
  desc  "
    In a reverse proxy configuration, NGINX acts as a client when communicating with an upstream server. To secure this server-to-server connection based on a Zero Trust principle, mutual TLS (mTLS) must be used. This is achieved by configuring NGINX to present its own client certificate to the upstream server. The upstream server then authenticates NGINX based on this certificate, ensuring that only trusted proxies can access backend services.

    Authenticating the proxy's connection to the upstream server via a client certificate provides strong, cryptographic proof of identity. This is vastly superior to weaker authentication methods like IP whitelisting, which can be spoofed. In a modern microservices or cloud environment, mTLS is a cornerstone of network security, as it prevents unauthorized services from making requests to sensitive backends, thereby mitigating lateral movement attacks.
  "
  desc  'rationale', "
    In a reverse proxy configuration, NGINX acts as a client when communicating with an upstream server. To secure this server-to-server connection based on a Zero Trust principle, mutual TLS (mTLS) must be used. This is achieved by configuring NGINX to present its own client certificate to the upstream server. The upstream server then authenticates NGINX based on this certificate, ensuring that only trusted proxies can access backend services.

    Authenticating the proxy's connection to the upstream server via a client certificate provides strong, cryptographic proof of identity. This is vastly superior to weaker authentication methods like IP whitelisting, which can be spoofed. In a modern microservices or cloud environment, mTLS is a cornerstone of network security, as it prevents unauthorized services from making requests to sensitive backends, thereby mitigating lateral movement attacks.
  "
  desc  'check', "
    Run the following command to inspect the fully loaded NGINX configuration for the required directives:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(proxy_ssl_certificate|proxy_ssl_certificate_key)'
    ```
    Verify that the output includes both `proxy_ssl_certificate` and `proxy_ssl_certificate_key` directives with the correct paths within the relevant location block.

    Note: A complete audit is two-sided. You must also verify that the upstream server is configured to require and validate client certificates against a trusted CA. This part of the audit is outside the scope of the NGINX configuration itself.
  "
  desc  'fix', "
    Implementing mTLS requires configuration on both the NGINX proxy (the client) and the upstream server (the server). This example assumes you have a simple internal CA.

    Prerequisite: Create a CA
    ```
    # Create CA Key
    openssl genrsa -out my-ca.key 4096
    # Create CA Certificate
    openssl req -x509 -new -nodes -key my-ca.key -sha256 -days 3650 -out my-ca.crt
    ```

    Step 1: Configure the Upstream Server to Require Client Certificates

    The upstream server must be configured to request and verify client certificates against your CA. (If your upstream is also NGINX, the config would look like this):

    ```
    # On the Upstream Server's configuration
    server {
        listen 443 ssl;
        # ... other ssl directives ...

        ssl_client_certificate  /path/to/my-ca.crt; # The CA to verify against
        ssl_verify_client on;                       # Require a valid client cert
    }
    ```

    Step 2: Create and Sign a Client Certificate for NGINX

    On your NGINX proxy, create a key and a certificate signing request (CSR).

    ```
    # Create a key for the NGINX proxy
    openssl genrsa -out      nginx-client.key 4096
    # Create CSR
    openssl req    -new -key nginx-client.key -out nginx-client.csr
    ```

    Sign this CSR with your CA to create the client certificate:
    ```
    openssl x509  -req -in nginx-client.csr -CA my-ca.crt -CAkey my-ca.key -CAcreateserial -out nginx-client.crt -days 365
    ```
    Step 3: Configure NGINX to Present its Client Certificate

    In your NGINX reverse proxy configuration, use the generated client certificate and key.

    ```
    # In your reverse proxy's location block
    location /api/ {
        proxy_pass                 https://your-upstream-server;

        # Present this client cert to the upstream
        proxy_ssl_certificate     /etc/nginx/ssl/nginx-client.crt;
        proxy_ssl_certificate_key /etc/nginx/ssl/nginx-client.key;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.9'
  tag cis_rid:               '4.1.9'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040109r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  proxy_pass_locations = conf.http.servers.flat_map(&:locations).select { |l| !Array(l.params['proxy_pass']).empty? }

  if proxy_pass_locations.empty?
    describe 'NGINX upstream client certificate (proxy_ssl_certificate)' do
      skip 'not-applicable: no proxy_pass directives — NGINX is not acting as a reverse proxy.'
    end
  else
    offenders = proxy_pass_locations.each_with_object([]) do |loc, acc|
      cert = Array(loc.params['proxy_ssl_certificate']).flatten.first
      key  = Array(loc.params['proxy_ssl_certificate_key']).flatten.first
      acc << loc.params.to_s unless cert && key
    end
    describe 'NGINX proxy_pass locations missing proxy_ssl_certificate / proxy_ssl_certificate_key' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
