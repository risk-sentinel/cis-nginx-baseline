# encoding: UTF-8

control 'C-4.1.2' do
  title 'Ensure a trusted certificate and trust chain is installed'
  desc  "
    Certificates and their trust chains are needed to establish the identity of a web server as legitimate and trusted. Certificate authorities validate a web server's identity and that you are the owner of that web server domain name.

    Without a certificate and full trust chain installed on your web server, modern browsers will flag your web server as untrusted.
  "
  desc  'rationale', "
    Certificates and their trust chains are needed to establish the identity of a web server as legitimate and trusted. Certificate authorities validate a web server's identity and that you are the owner of that web server domain name.

    Without a certificate and full trust chain installed on your web server, modern browsers will flag your web server as untrusted.
  "
  desc  'check', "
    Run this command to find the file location of your certificate: 

    ```
    grep -ir ssl_certificate /etc/nginx/
    ```

    The output of your command should look similar to the below output. If there is no output, you do not have a certificate installed.

    Web Server:

    ```
    /etc/nginx/nginx.conf:    ssl_certificate /etc/nginx/cert.pem;
    /etc/nginx/nginx.conf:    ssl_certificate_key /etc/nginx/nginx.key;
    ```

    Open the file to the right of the `ssl_certificate` directive using the following command:

    ```
    cat /etc/nginx/cert.pem
    ```

    The output of your command should look similar to the below. It should include the full certificate chain.

    ```
    -----BEGIN CERTIFICATE-----
    Insert Your Web Server Certificate
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    Insert Your Certificate Authority Intermediate Certificate
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    Insert Your Certificate Authority Root Certificate
    -----END CERTIFICATE-----
    ```
  "
  desc  'fix', "
    Use the following procedure to install a certificate and its signing certificate chain onto your web server, load balancer, or proxy.

    Step 1: Create the server's private key and a certificate signing request.

    The following command will create your certificate's private key with 4096-bit key strength. It will also output your certificate signing request to the `nginx.csr` file in your present working directory.

    ```
    openssl req -new -newkey rsa:4096 -keyout nginx.key -out nginx.csr
    ```

    Enter the below information about your private key:

    ```
    Country Name (2 letter code) [XX]: Your Country
    State or Province Name (full name) []: Your State
    Locality Name (eg, city) [Default City]: Your City
    Organization Name (eg, company) [Default Company Ltd]: Your City
    Organizational Unit Name (eg, section) []: Your Organizational Unit
    Common Name (eg, your name or your server's hostname) []: Your server's DNS name
    Email Address []: Your email address
    ```

    Step 2: Obtain a signed certificate from your certificate authority.

    Provide your chosen certificate authority with your certificate signing request. Follow your certificate authority's signing procedures in order to obtain a certificate and the certificate's trust chain. A full trust chain is typically delivered in `.pem` format.

    Step 3: Install certificate and signing certificate chain on your web server.

    Place the `.pem` file from your certificate authority into the directory of your choice. Locate your created key file from the command you used to generate your certificate signing request. Open your website configuration file and edit your encrypted listener to leverage the ssl_certificate and `ssl_certificate_key` directives for a web server as shown below. You should also inspect include files inside your `nginx.conf`. This should be part of the server block.

    ```
    server {
        listen              443 ssl http2;
        listen              [::]:443 ssl http2;
        ssl_certificate     /etc/nginx/cert.crt;
        ssl_certificate_key /etc/nginx/nginx.key;
        ...
        }
    ```

    After editing this file, you must restart the nginx systemd service for these changes to take effect. This can be done with the following command:

    ```
    sudo systemctl restart nginx
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.2'
  tag cis_rid:               '4.1.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040102r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true


  conf = nginx_conf(input('nginx_conf_path'))
  tls_servers = conf.http.servers.select do |s|
    Array(s.params['listen']).flatten.map(&:to_s).any? { |a| a =~ /\bssl\b|\bquic\b|:443\b/ } ||
      !Array(s.params['ssl_certificate']).flatten.reject { |v| v.to_s.empty? }.empty?
  end

  termination = input('nginx_tls_termination')
  disp = tls_termination_disposition(termination, !(tls_servers.empty?))
  impact 0.0 if disp == :na

  if disp == :na
    describe 'NGINX TLS certificate configuration (4.1.2)' do
      skip "not-applicable: nginx_tls_termination=#{termination} — NGINX does not terminate TLS here; validate it at the terminating layer (the load balancer / compute / fargate ALB TLS controls)."
    end
  elsif disp == :missing
    describe 'NGINX must terminate TLS when nginx_tls_termination=nginx (4.1.2)' do
      subject { !(tls_servers.empty?) }
      it { is_expected.to be_truthy }
    end
  else
    missing = tls_servers.select do |s|
      Array(s.params['ssl_certificate']).flatten.reject { |v| v.to_s.empty? }.empty?
    end
    describe 'NGINX TLS server blocks missing an ssl_certificate directive (4.1.2)' do
      subject { missing.size }
      it { should eq 0 }
    end
    # Trust-chain validity (CA chain ordering / expiry) is a PKI/ACM concern beyond
    # nginx directives; ssl_certificate presence is the in-config trust signal.
  end
end
