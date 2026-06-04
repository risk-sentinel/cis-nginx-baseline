# encoding: UTF-8

control 'C-5.1.2' do
  title 'Ensure only approved HTTP methods are allowed'
  desc  "
    Following the principle of least functionality, an NGINX server should be configured to reject any HTTP methods that are not explicitly required by the application. While standard web browsing typically only needs `GET`, `POST`, and `HEAD`, modern RESTful APIs might require methods like `PUT`, `PATCH`, or `DELETE`. Any method not essential for the application's functionality should be blocked at the web server level.

    Disabling unused HTTP methods mitigates the risk of unintended server interaction and can prevent certain classes of web application attacks. For example, if an attacker finds a way to bypass application-layer authentication, an enabled but unused `PUT` or `DELETE` method on the web server could potentially lead to unauthorized file modification or deletion. By explicitly denying such methods, NGINX ensures that requests never even reach the backend application and therefore significantly reducing the attack surface.
  "
  desc  'rationale', "
    Following the principle of least functionality, an NGINX server should be configured to reject any HTTP methods that are not explicitly required by the application. While standard web browsing typically only needs `GET`, `POST`, and `HEAD`, modern RESTful APIs might require methods like `PUT`, `PATCH`, or `DELETE`. Any method not essential for the application's functionality should be blocked at the web server level.

    Disabling unused HTTP methods mitigates the risk of unintended server interaction and can prevent certain classes of web application attacks. For example, if an attacker finds a way to bypass application-layer authentication, an enabled but unused `PUT` or `DELETE` method on the web server could potentially lead to unauthorized file modification or deletion. By explicitly denying such methods, NGINX ensures that requests never even reach the backend application and therefore significantly reducing the attack surface.
  "
  desc  'check', "
    1. Configuration Inspection:

    Run the following command to analyze the fully loaded NGINX configuration for any method-limiting directives:
    ```
    nginx -T 2>/dev/null | grep -E '(\\$request_method|limit_except)'
    ```
    Review the configuration to ensure that either a `limit_except` block or an `if ($request_method)` block is correctly implemented for the relevant location.

    2. Active Testing:

    Send a request with a non-approved method (e.g., `OPTIONS` or `DELETE`) using `curl` and verify that the server responds with the correct status code, not a `200 OK` or `404 Not Found`.

    ```
    # Send a disallowed OPTIONS request
    curl -X OPTIONS -I https://example.loc/api.html
    ```

    Expected Output: The server should return either `HTTP/1.1 405 Not Allowed` or `HTTP/1.1 444 Connection Closed Without Response`. Any other `2xx` or `4xx` code indicates a potential misconfiguration.
  "
  desc  'fix', "
    There are two recommended methods to restrict HTTP verbs.

    Method 1 (Preferred): Using `limit_except`
    This directive is designed for this purpose and is considered the cleanest approach. It restricts all methods except for the ones listed.

    ```

    location /api_login/ {

        # Only allow GET, HEAD, and POST methods for this location.
        limit_except GET HEAD POST {
            deny all;
        }

        # ... other directives ...
    }
    ```

    Method 2 (Alternative): Using an `if` condition
    This method offers more flexibility, such as returning a non-standard status code like `444`, which simply closes the connection without sending a response header.


    ```
    location / {

        # If the request method is NOT one of GET, HEAD, or POST
        if ($request_method !~ ^(GET|HEAD|POST)$) {
            # --> close the connection immediately.
            return 444;
        }

        # ... other directives ...
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-4 (11)', 'SA-8']
  tag cci:                   ['CCI-002668', 'CCI-000664']
  tag cis_number:            '5.1.2'
  tag cis_rid:               '5.1.2'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050102r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'
  tag exec_validated:        false


  approved = Array(input('nginx_approved_http_methods')).map { |m| m.to_s.upcase }
  if approved.empty?
    describe 'NGINX approved HTTP methods (5.1.2)' do
      skip 'attestation-required: the approved method set varies per location (REST needs PUT/PATCH/DELETE; static assets GET/HEAD); set nginx_approved_http_methods to enable automated limit_except enforcement, or attest per workload.'
    end
  else
    conf = nginx_conf(input('nginx_conf_path'))
    methods = []
    conf.http.servers.each do |s|
      s.locations.each do |l|
        Array(l.params['limit_except']).each do |blk|
          # limit_except parses as {'_' => [methods...], <nested directives>};
          # the permitted methods are under the '_' key.
          methods.concat(blk.is_a?(Hash) ? Array(blk['_']).flatten : Array(blk))
        end
      end
    end
    methods = methods.flat_map { |v| v.to_s.split }.map(&:upcase).uniq.reject(&:empty?)

    if methods.empty?
      describe 'NGINX HTTP method restriction (5.1.2)' do
        it 'defines at least one limit_except block when approved methods are configured' do
          expect(methods).not_to be_empty
        end
      end
    else
      describe 'NGINX limit_except methods outside the approved set (5.1.2)' do
        subject { methods.reject { |m| approved.include?(m) } }
        it { should be_empty }
      end
    end
  end
end
