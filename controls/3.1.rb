# encoding: UTF-8

control 'C-3.1' do
  title 'Ensure detailed logging is enabled'
  desc  "
    System logging must be configured to meet organizational security and privacy policies. Detailed logs provide the necessary context (event source, timestamp, user, network data) for incident response and forensic analysis. Modern logging strategies favor structured formats (JSON) over unstructured text to facilitate parsing by SIEM solutions.

    Note: Sensitive information (e.g., session tokens, PII in query strings) should be excluded or masked in logs to prevent data leaks.

    Detailed logs are the foundation of effective incident response. CIS Control 8.5 (\"Collect Detailed Audit Logs\") recommends capturing event sources, dates, users, timestamps, and network addresses. Traditional text logs require complex, fragile Regex parsing that breaks easily when formats change. Structured logging (JSON) solves this by providing a self-describing format that is natively ingested by modern analysis tools (SIEM), ensuring that critical forensic data is always indexable and searchable.
  "
  desc  'rationale', "
    System logging must be configured to meet organizational security and privacy policies. Detailed logs provide the necessary context (event source, timestamp, user, network data) for incident response and forensic analysis. Modern logging strategies favor structured formats (JSON) over unstructured text to facilitate parsing by SIEM solutions.

    Note: Sensitive information (e.g., session tokens, PII in query strings) should be excluded or masked in logs to prevent data leaks.

    Detailed logs are the foundation of effective incident response. CIS Control 8.5 (\"Collect Detailed Audit Logs\") recommends capturing event sources, dates, users, timestamps, and network addresses. Traditional text logs require complex, fragile Regex parsing that breaks easily when formats change. Structured logging (JSON) solves this by providing a self-describing format that is natively ingested by modern analysis tools (SIEM), ensuring that critical forensic data is always indexable and searchable.
  "
  desc  'check', "
    1. Verify Log Format Configuration:

    Inspect the `log_format` directives in your configuration:
    ```
    nginx -T 2>/dev/null | grep -i \"log_format\"
    ```
    Evaluation:

    - Confirm that a detailed format (preferably JSON) is defined.
    - Verify that the format includes critical fields: `$time_iso8601`, `$remote_addr`, `$remote_user`, `$request`, `$status`, `$http_user_agent`.

    2. Verify Access Log Usage:

    Check that the defined format is actually used by the `access_log` directive:
    ```
    nginx -T 2>/dev/null | grep \"access_log\"
    ```
    Evaluation:

    - The `access_log` directive should reference the detailed format name (e.g., `access_log /var/log/nginx/access.json main_access_json;`).
  "
  desc  'fix', "
    Define a detailed log format in the `http` block of `/etc/nginx/nginx.conf`. It is highly recommended to use JSON format for compatibility with modern SIEM tools.

    Recommended Configuration (JSON):

    ```
    http {
        log_format main_access_json escape=json '{'
          '\"timestamp\":         \"$time_iso8601\",'
          '\"remote_addr\":       \"$remote_addr\",'
          '\"remote_user\":       \"$remote_user\",'
          '\"server_name\":       \"$server_name\",'
          '\"request_method\":    \"$request_method\",'
          '\"request_uri\":       \"$request_uri\",'
          '\"status\":            $status,'
          '\"body_bytes_sent\":   $body_bytes_sent,'
          '\"http_referer\":      \"$http_referer\",'
          '\"http_user_agent\":   \"$http_user_agent\",'
          '\"x_forwarded_for\":   \"$http_x_forwarded_for\",'
          '\"request_id\":        \"$request_id\"'
        '}';

        # Apply the format globally or per server
        access_log /var/log/nginx/access.json main_access_json;
    }
    ```

    Legacy Configuration (Text-based):

    If JSON is not feasible, ensure the text format captures all necessary fields:

    ```
    log_format main_detailed '$remote_addr - $remote_user [$time_local] '
                             '\"$request\" $status $body_bytes_sent '
                             '\"$http_referer\" \"$http_user_agent\" '
                             '\"$http_x_forwarded_for\"';

    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.1'
  tag cis_rid:               '3.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-0301r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  log_formats = Array(nginx_http_values(nginx_conf(input('nginx_conf_path')), 'log_format'))
  required_vars = %w[$remote_addr $time_local $request $status $body_bytes_sent $http_user_agent]
  offenders = log_formats.each_with_object([]) do |fmt_args, acc|
    body = Array(fmt_args)[1..].to_a.join(' ')
    missing = required_vars - required_vars.select { |v| body.include?(v) }
    acc << "#{Array(fmt_args).first}:missing=#{missing.join(',')}" unless missing.empty?
  end

  describe 'NGINX log_format definitions missing CIS-recommended fields ($remote_addr, $time_local, $request, $status, $body_bytes_sent, $http_user_agent)' do
    subject { offenders }
    it { should be_empty }
  end

  describe 'NGINX has at least one log_format defined' do
    subject { log_formats }
    it { should_not be_empty }
  end
end
