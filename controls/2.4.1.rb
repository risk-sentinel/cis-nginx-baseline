# encoding: UTF-8

control 'C-2.4.1' do
  title 'Ensure NGINX only listens for network connections on authorized ports'
  desc  "
    NGINX should be configured to listen only on authorized ports and protocols. While traditional HTTP/1.1 and HTTP/2 use TCP ports `80` and `443`, modern HTTP/3 (QUIC) utilizes UDP port `443`. Ensuring that NGINX binds only to approved interfaces and ports minimizes the attack surface.

    Limiting listening ports to authorized values ensures that no hidden or unintended services are exposed via NGINX. It also enforces strict control over which protocols (TCP vs. UDP) are accessible, which is particularly important with the introduction of UDP-based HTTP/3 traffic alongside traditional TCP traffic.
  "
  desc  'rationale', "
    NGINX should be configured to listen only on authorized ports and protocols. While traditional HTTP/1.1 and HTTP/2 use TCP ports `80` and `443`, modern HTTP/3 (QUIC) utilizes UDP port `443`. Ensuring that NGINX binds only to approved interfaces and ports minimizes the attack surface.

    Limiting listening ports to authorized values ensures that no hidden or unintended services are exposed via NGINX. It also enforces strict control over which protocols (TCP vs. UDP) are accessible, which is particularly important with the introduction of UDP-based HTTP/3 traffic alongside traditional TCP traffic.
  "
  desc  'check', "
    1. Inspect Configuration:

    Run the following command to inspect all listen directives in the loaded configuration:
    ```
    nginx -T 2>/dev/null | grep -r \"listen\"
    ```
    Evaluation:

    Review the output for unauthorized ports. A modern secure configuration typically includes:

    - `listen 80;`       (TCP) - Often used only for redirecting to HTTPS.
    - `listen 443 ssl;`  (TCP) - For HTTP/1.1 and HTTP/2.
    - `listen 443 quic;` (UDP) - For HTTP/3 (QUIC).

    Example Output:

    ```
    server {

        listen  80;
        listen 443 ssl;
        listen 443 quic reuseport; # HTTP/3 (UDP)
        ...
    }
    ```

    Ensure that no other ports (e.g., `8080`, `8443`) are open unless explicitly authorized for internal services or management interfaces.

    2. Verify System Listening Ports:

    Optionally, verify what the process is actually binding to on the OS level:
    ```
    netstat -tulpen | grep -i nginx
    ```
    - Look for `tcp` lines for standard traffic.
    - Look for `udp` lines (e.g., `*:443`) if HTTP/3 is enabled.
  "
  desc  'fix', "
    Remove or comment out any `listen` directives that bind to unauthorized ports.

    For HTTP/3 (QUIC) Support:
    Ensure that you explicitly authorize and configure UDP port `443` in addition to TCP port `443`.

    ```
    server {

        # Standard HTTPS (TCP)
        listen 443 ssl;

        # HTTP/3 (UDP)
        listen 443 quic reuseport;
    
        # ... SSL/TLS configuration ...
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-4 (11)', 'SA-8']
  tag cci:                   ['CCI-002668', 'CCI-000664']
  tag cis_number:            '2.4.1'
  tag cis_rid:               '2.4.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020401r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  authorized = Array(input('nginx_authorized_ports')).map(&:to_s)
  listen_entries = []
  nginx_conf(input('nginx_conf_path')).http.servers.each do |server|
    Array(server.params['listen']).each do |args|
      listen_entries << Array(args).first.to_s
    end
  end

  extract_port = lambda do |entry|
    first = entry.split.first.to_s
    case first
    when /\]:(\d+)\z/ then Regexp.last_match(1)
    when /:(\d+)\z/   then Regexp.last_match(1)
    when /\A(\d+)\z/  then first
    end
  end

  offenders = listen_entries.each_with_object([]) do |entry, acc|
    port = extract_port.call(entry)
    acc << entry if port.nil? || !authorized.include?(port)
  end

  describe 'NGINX `listen` directives binding ports outside nginx_authorized_ports' do
    subject { offenders.uniq }
    it { should be_empty }
  end
end
