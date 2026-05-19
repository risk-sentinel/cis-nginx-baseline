# encoding: UTF-8

control 'C-3.3' do
  title 'Ensure error logging is enabled and set to the info logging level'
  desc  "
    The `error_log` directive configures logging for server errors and operational messages. Unlike access logs, error logs capture diagnostic information about failed requests, upstream connection issues, and configuration errors. The log level determines the verbosity of these messages and should be set to capture sufficient detail (typically `notice` or `info`) without overwhelming the storage system.

    While access logs capture incoming request patterns, error logs provide the internal system context required to diagnose why a request failed. They are essential for identifying:

    1. Upstream Failures: Connection timeouts or refused connections to backend servers (e.g., application server is down).

    2. Process Anomalies: Unexpected worker process terminations or restarts, which may indicate resource exhaustion or exploitation attempts.

    3. Configuration Errors: Invalid request handling that NGINX rejects before logging to access logs (e.g., header size limits exceeded).

    Without error logs, an administrator sees a \"`500 Internal Server Error`\" in the access log but has no way to determine the root cause.
  "
  desc  'rationale', "
    The `error_log` directive configures logging for server errors and operational messages. Unlike access logs, error logs capture diagnostic information about failed requests, upstream connection issues, and configuration errors. The log level determines the verbosity of these messages and should be set to capture sufficient detail (typically `notice` or `info`) without overwhelming the storage system.

    While access logs capture incoming request patterns, error logs provide the internal system context required to diagnose why a request failed. They are essential for identifying:

    1. Upstream Failures: Connection timeouts or refused connections to backend servers (e.g., application server is down).

    2. Process Anomalies: Unexpected worker process terminations or restarts, which may indicate resource exhaustion or exploitation attempts.

    3. Configuration Errors: Invalid request handling that NGINX rejects before logging to access logs (e.g., header size limits exceeded).

    Without error logs, an administrator sees a \"`500 Internal Server Error`\" in the access log but has no way to determine the root cause.
  "
  desc  'check', "
    1. Verify Configuration:

    Check the fully loaded configuration for error log settings:
    ```
    nginx -T 2>/dev/null | grep -i \"error_log\"
    ```
    Evaluation:

    - Presence: Verify that `error_log` is defined globally in the `main` context (or `http` block).
    - Destination: Ensure it points to a valid local file (e.g., `/var/log/nginx/error.log`) accessible for ingestion by log shippers.
    - Level: Confirm the level is set according to your internal \"Monitoring and Logging\" policy.
    - Fail: If `error_log` points to `/dev/null` or the level is set to `crit`, `alert`, or `emerg` (which suppresses too many relevant warnings).
  "
  desc  'fix', "
    Configure the `error_log` directive in the `main` context (at the top of `nginx.conf`) to capture operational events.

    Configuration Example:

    ```
    # Log errors to a specific file with the 'notice' level
    error_log /var/log/nginx/error.log notice;

    http {
        # ...
    }
    ```

    Note: The specific logging level should be aligned with the organization's \"Monitoring and Logging\" Policy, balancing the need for forensic detail against storage and processing costs. Typically, `info` or `notice` is recommended.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.3'
  tag cis_rid:               '3.3'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-0303r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  values = Array(nginx_conf(input('nginx_conf_path')).params['error_log']).flatten
  acceptable_levels = %w[debug info notice warn]

  if values.empty?
    describe 'NGINX error_log directive' do
      subject { values }
      it { should_not be_empty }
    end
  else
    # error_log <path> [level]; level defaults to error if omitted.
    level = values.length >= 2 ? values[1].to_s : 'error'
    describe 'NGINX error_log level — must be info or more verbose (debug, info, notice, warn)' do
      subject { level }
      it { should be_in acceptable_levels }
    end
  end
end
