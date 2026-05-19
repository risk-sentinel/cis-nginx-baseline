# encoding: UTF-8

control 'C-3.2' do
  title 'Ensure access logging is enabled'
  desc  "
    The `access_log` directive enables the logging of client requests. While NGINX enables this by default, it allows granular control per server or location context. Based on enterprise requirements, the log should be enriched with relevant variables or converted to structured JSON format for modern SIEM integration. Refer to Recommendation 3.1 for detailed configuration of log formats and variables. Ensure that access logging is active for all critical services.

    Access logs are the primary record of system usage, detailing who accessed what resources and when and general troubleshooting. Without active access logs, incident responders are blind to web-based attacks (such as SQL injection, XSS probing, or Brute Force attempts) and auditors cannot verify compliance or user activity. Disabling logs globally (`access_log off;`) effectively destroys the forensic chain of custody for security events.
  "
  desc  'rationale', "
    The `access_log` directive enables the logging of client requests. While NGINX enables this by default, it allows granular control per server or location context. Based on enterprise requirements, the log should be enriched with relevant variables or converted to structured JSON format for modern SIEM integration. Refer to Recommendation 3.1 for detailed configuration of log formats and variables. Ensure that access logging is active for all critical services.

    Access logs are the primary record of system usage, detailing who accessed what resources and when and general troubleshooting. Without active access logs, incident responders are blind to web-based attacks (such as SQL injection, XSS probing, or Brute Force attempts) and auditors cannot verify compliance or user activity. Disabling logs globally (`access_log off;`) effectively destroys the forensic chain of custody for security events.
  "
  desc  'check', "
    1. Verify Configuration:

    Inspect the fully loaded configuration for log settings:
    ```
    nginx -T 2>/dev/null | grep -i \"access_log\"
    ```
    Evaluation:

    - Destination Check: Verify that `access_log` directives point to a valid local file path (e.g., `/var/log/nginx/access.json`) for ingestion by log shippers.
    - Status Check: Identify any instances of `access_log off;`.

    - Pass: If `access_log off;` is absent, or strictly limited to non-critical assets (e.g., `location = /favicon.ico`, static assets, or internal health checks).
    - Fail: If `access_log off;` is applied globally in the `http` block or to `server` blocks handling business logic.
  "
  desc  'fix', "
    Enable access logging in the `http` block to set a secure global default, or configure it explicitly within specific `server` blocks. It is recommended to use the detailed log format defined in Recommendation 3.1.

    Configuration Example:

    ```
    http {

        # Enable global logging using the detailed JSON format from Rec 3.1
        access_log /var/log/nginx/access.json main_access_json;
    
        server {
        
            # Inherits the global log setting, or can be overridden:
            access_log /var/log/nginx/example.com.access.json main_access_json;
        
            location / {
                # ...
            }

            # Exception: Disable logging for favicon to reduce noise (Optional)
            location = /favicon.ico {
                access_log    off;
                log_not_found off;
            }
        }
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.2'
  tag cis_rid:               '3.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-0302r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  http_access_log = Array(conf.http.params['access_log']).flatten.compact
  http_disabled = http_access_log.any? { |v| v.to_s.strip.casecmp('off').zero? }

  describe 'NGINX http.access_log directive — must be present and not "off"' do
    subject { http_access_log }
    it { should_not be_empty }
  end

  describe 'NGINX http.access_log not disabled at the http level' do
    subject { http_disabled }
    it { should eq false }
  end
end
