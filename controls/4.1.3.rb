# encoding: UTF-8

control 'C-4.1.3' do
  title 'Ensure private key permissions are restricted'
  desc  "
    The server's and potentially its vhost's private keys should be protected from unauthorized access by limiting access based on the principle of least privilege.

    A server's private key file should be restricted to `400` permissions. This ensures only the owner of the private key file can access it. This is the minimum necessary permissions for the server to operate. If the private key file is not protected, an unauthorized user with access to the server may be able to find the private key file and use it to decrypt traffic sent to your server.
  "
  desc  'rationale', "
    The server's and potentially its vhost's private keys should be protected from unauthorized access by limiting access based on the principle of least privilege.

    A server's private key file should be restricted to `400` permissions. This ensures only the owner of the private key file can access it. This is the minimum necessary permissions for the server to operate. If the private key file is not protected, an unauthorized user with access to the server may be able to find the private key file and use it to decrypt traffic sent to your server.
  "
  desc  'check', "
    Verify the permissions on the key file are `400`. This can be found by running the following command. You should replace `/etc/nginx/nginx.key` with the location of your key file.

    ```
    find /etc/nginx/ -name '*.key' -exec stat -Lc \"%n %a\" {} +
    ```

    The output should show mode 400 or more restrictive

    Example:

    ```
    /etc/nginx/nginx.key 400
    ```
  "
  desc  'fix', "
    Run the following command to remove excessive permissions on key files in the `/etc/nginx/ directory`.

    Note: The directory `/etc/nginx/` should be replaced with the location of your key file.

    ```
    find /etc/nginx/ -name '*.key' -exec chmod u-wx,go-rwx {} +
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.1.3'
  tag cis_rid:               '4.1.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-040103r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  key_paths = Array(nginx_http_values(nginx_conf(input('nginx_conf_path')), 'ssl_certificate_key')).map { |args| Array(args).first.to_s }
  conf = nginx_conf(input('nginx_conf_path'))
  conf.http.servers.each do |s|
    key_paths.concat(Array(s.params['ssl_certificate_key']).map { |args| Array(args).first.to_s })
  end
  key_paths.uniq!

  termination = input('nginx_tls_termination')
  disp = tls_termination_disposition(termination, !(key_paths.empty?))
  impact 0.0 if disp == :na

  if disp == :na
    describe 'NGINX ssl_certificate_key directives' do
      skip "not-applicable: nginx_tls_termination=#{termination} — NGINX does not terminate TLS here; validate it at the terminating layer (the load balancer / compute / fargate ALB TLS controls)."
    end
  elsif disp == :missing
    describe 'NGINX must terminate TLS when nginx_tls_termination=nginx (4.1.3)' do
      subject { !(key_paths.empty?) }
      it { is_expected.to be_truthy }
    end
  else
    offenders = key_paths.each_with_object([]) do |path, acc|
      next unless file(path).exist?
      mode = file(path).mode.to_s(8).rjust(4, '0')
      group = mode[-2].to_i
      other = mode[-1].to_i
      acc << "#{path}:mode=#{mode}" if (other & 0o7) != 0 || (group & 0o5) != 0
    end
    describe 'NGINX TLS private key files with permissions broader than 0640 / 0600' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
