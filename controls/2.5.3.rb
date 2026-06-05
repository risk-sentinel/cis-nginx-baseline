# encoding: UTF-8

control 'C-2.5.3' do
  title 'Ensure hidden file serving is disabled'
  desc  "
    Hidden files and directories (starting with a dot, e.g., `.git`, `.env`) often contain sensitive metadata, version control history, or environment configurations. Serving these files should be globally disabled.

    Version control systems (Git, SVN) and editors create hidden files that may unintentionally be deployed to the web root. If accessible, files like `.git/config` or `.env` can leak database credentials, source code, and infrastructure details, leading to full system compromise. Blocking requests to any path starting with a dot (`.`) neutralizes this risk.
  "
  desc  'rationale', "
    Hidden files and directories (starting with a dot, e.g., `.git`, `.env`) often contain sensitive metadata, version control history, or environment configurations. Serving these files should be globally disabled.

    Version control systems (Git, SVN) and editors create hidden files that may unintentionally be deployed to the web root. If accessible, files like `.git/config` or `.env` can leak database credentials, source code, and infrastructure details, leading to full system compromise. Blocking requests to any path starting with a dot (`.`) neutralizes this risk.
  "
  desc  'check', "
    1. Check Configuration:

    Search the loaded configuration for hidden file protection rules:
    ```
    nginx -T 2>/dev/null | grep \"location.*\\\\\\.\"
    ```
    Evaluation:

    - Look for a block like `location ~ /\\. { deny all; ... }`.

    2. Functional Test (Recommended):

    Try to access a dummy hidden file:
    ```
    curl -k -I https://127.0.0.1/.git/HEAD
    ```
    Evaluation:

    - PASS: Returns `403 Forbidden` or `404 Not Found`.
    - FAIL: Returns `200 OK` (if file exists) or the content of the file.
  "
  desc  'fix', "
    To restrict access to hidden files, add the configuration block below inside each server block.

    Option A: Direct Configuration

    Place this block directly into your `server` contexts:

    ```
    # Allow Let's Encrypt validation (must be before the deny rule)
    location ^~ /.well-known/acme-challenge/ {
        allow all;
        default_type \"text/plain\";
    }

    # Deny access to all other hidden files
    location ~ /\\. {
        deny all;
        return 404;
    }
    ```

    Option B: Using a Shared Snippet (Recommended)

    Create a reusable snippet file (e.g., `/etc/nginx/snippets/deny-hidden.conf`) containing the rules above, and include it in your `server` blocks:

    1. Create `/etc/nginx/snippets/deny-hidden.conf` with the content from Option A.
    2. Security Check: Ensure the new file has restrictive permissions (Owner: `root:root`, Mode: `640`) as described in Recommendation 2.3.2.
    3. Add the include directive to your server blocks:

    ```
    server {
        # Modern HTTP/3 (QUIC) and HTTP/2 Setup
    
        listen 443 ssl;            # TCP for HTTP/1.1 & HTTP/2
        listen 443 quic reuseport; # UDP for HTTP/3
        http2 on;                  # Explicitly enable HTTP/2 (since NGINX 1.25.1)
    
        server_name example.com;
    
        include /etc/nginx/snippets/deny-hidden.conf;
    
        # ... rest of configuration
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.5.3'
  tag cis_rid:               '2.5.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020503r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  conf_files = [input('nginx_conf_path')] + Dir.glob('/etc/nginx/conf.d/*.conf')
  conf_content = conf_files.map { |f| file(f).exist? ? file(f).content.to_s : '' }.join("\n")
  has_hidden_deny = !!(conf_content =~ /location\s+[~^]\s*[\"']?\s*\/?\?\.\.?[\"']?\s*\{[^}]*(deny|return)/m)

  describe 'NGINX location block denying hidden-file (dotfile) access' do
    subject { has_hidden_deny }
    it { should eq true }
  end
end
