# encoding: UTF-8

control 'C-4.1.1' do
  title 'Ensure HTTP is redirected to HTTPS'
  desc  "
    Browsers and clients establish encrypted connections with servers by leveraging HTTPS. Requests leveraging HTTP are unencrypted. Unencrypted requests should be redirected so they are encrypted. Any listening HTTP port on your web server should redirect to a server profile that uses encryption. The default HTTP (unencrypted) port is `80`.

    Redirecting user agent traffic to HTTPS helps to ensure all user traffic is encrypted. Modern browsers alert users that your website is insecure when HTTPS is not used. This can decrease user trust in your website and ultimately result in decreased use of your web services. Redirection from HTTP to HTTPS couples security with usability; users are able to access your website even if they lack the security awareness to use HTTPS over HTTP when requesting your website.
  "
  desc  'rationale', "
    Browsers and clients establish encrypted connections with servers by leveraging HTTPS. Requests leveraging HTTP are unencrypted. Unencrypted requests should be redirected so they are encrypted. Any listening HTTP port on your web server should redirect to a server profile that uses encryption. The default HTTP (unencrypted) port is `80`.

    Redirecting user agent traffic to HTTPS helps to ensure all user traffic is encrypted. Modern browsers alert users that your website is insecure when HTTPS is not used. This can decrease user trust in your website and ultimately result in decreased use of your web services. Redirection from HTTP to HTTPS couples security with usability; users are able to access your website even if they lack the security awareness to use HTTPS over HTTP when requesting your website.
  "
  desc  'check', "
    To verify your server listening configuration, check your web server or proxy configuration file. The default web server configuration file is `/etc/nginx/conf.d/default.conf`, and the default proxy configuration file is `/etc/nginx/nginx.conf`. The configuration file should return a statement redirecting to HTTPS. This should be similar to the code below, where cisecurity.org is used as an example.


    ```
    server {
        listen 80;

        server_name cisecurity.org;

        return 301 https://$host$request_uri;
    }
    ```
  "
  desc  'fix', "
    Edit your web server or proxy configuration file to redirect all unencrypted listening ports, such as port `80`, using a redirection through the return directive (cisecurity.org is used as an example server name).

    ```
    server {
        listen 80;

        server_name cisecurity.org;

        return 301 https://$host$request_uri;
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.1.1'
  tag cis_rid:               '4.1.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040101r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  conf = nginx_conf(input('nginx_conf_path'))
  port_80_servers = conf.http.servers.select do |s|
    Array(s.params['listen']).any? do |args|
      first = Array(args).first.to_s.split.first.to_s
      first == '80' || first =~ /:80\z/ || first == '[::]:80'
    end
  end

  if port_80_servers.empty?
    describe 'NGINX HTTP-to-HTTPS redirect' do
      skip 'not-applicable: no server block listens on port 80 — nothing to redirect.'
    end
  else
    offenders = port_80_servers.reject do |s|
      returns = Array(s.params['return']).flatten.join(' ')
      rewrites = Array(s.params['rewrite']).flatten.join(' ')
      returns =~ /\b(301|302|307|308)\b.*https:/i || rewrites =~ /https:/i
    end
    describe 'NGINX port-80 server blocks not redirecting to HTTPS' do
      subject { offenders.size }
      it { should eq 0 }
    end
  end
end
