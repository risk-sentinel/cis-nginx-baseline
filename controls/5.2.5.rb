# encoding: UTF-8

control 'C-5.2.5' do
  title 'Ensure rate limits by IP address are set'
  desc  "
    NGINX's `ngx_http_limit_req_module` provides a mechanism to limit the rate of incoming requests from a single client IP address, based on the \"leaky bucket\" algorithm. This is configured in two steps:

    1. `limit_req_zone`: This directive, defined in the `http` block, creates a shared memory zone that defines the bucket's parameters, such as the average request rate.

    2. `limit_req`: This directive, applied in a `server` or `location` block, enforces the rate limit using a specific zone and defines how \"bursts\" of traffic are handled.

    When a client exceeds the defined rate, NGINX will reject new requests with a `503 Service Temporarily Unavailable` error.

    Rate limiting is the primary defense against application-level, high-frequency attacks. Its main purpose is to prevent brute-force password guessing on login endpoints, API abuse by automated scripts, and aggressive content scraping. Unlike connection limiting (`limit_conn`), which focuses on slow, simultaneous connections, rate limiting (`limit_req`) targets clients making an excessive number of requests in a short period.
  "
  desc  'rationale', "
    NGINX's `ngx_http_limit_req_module` provides a mechanism to limit the rate of incoming requests from a single client IP address, based on the \"leaky bucket\" algorithm. This is configured in two steps:

    1. `limit_req_zone`: This directive, defined in the `http` block, creates a shared memory zone that defines the bucket's parameters, such as the average request rate.

    2. `limit_req`: This directive, applied in a `server` or `location` block, enforces the rate limit using a specific zone and defines how \"bursts\" of traffic are handled.

    When a client exceeds the defined rate, NGINX will reject new requests with a `503 Service Temporarily Unavailable` error.

    Rate limiting is the primary defense against application-level, high-frequency attacks. Its main purpose is to prevent brute-force password guessing on login endpoints, API abuse by automated scripts, and aggressive content scraping. Unlike connection limiting (`limit_conn`), which focuses on slow, simultaneous connections, rate limiting (`limit_req`) targets clients making an excessive number of requests in a short period.
  "
  desc  'check', "
    This is a manual check requiring context.

    1. Run the following command to find rate-limiting rules:
    ```
    nginx -T 2>/dev/null | grep -E '^\\s*(limit_req_zone|limit_req)'
    ```
    2. Manually evaluate the findings:

    - Is a `limit_req_zone` defined in the `http` block?
    - Important, where is `limit_req` applied? Is it applied globally (`server` Block or `location /`)? This is a high risk. Or is it applied to specific endpoints like `/login`? Which is best practice.
    - Are the `rate` and `burst` values reasonable for the protected endpoint?
  "
  desc  'fix', "
    First, define a shared memory zone in the `http` block. Then, apply a carefully tuned limit only to the specific `location` blocks that require protection.

    Understanding the \"Leaky Bucket\" Parameters:

    - `rate`: The average rate at which the bucket \"leaks\" (requests are processed). `5r/s` means 5 requests per second.
    - `burst`: The size of the bucket. It's the number of \"token\" requests a client can make in excess of the defined rate. A `burst=10` allows a client to burst up to 10 requests instantly before the rate limit kicks in.
    - `nodelay`: Without `nodelay`, excess requests in a burst are queued and processed at the defined `rate` (slowing the client down). With `nodelay`, excess requests are processed immediately as long as they fit in the burst \"bucket\", and only requests beyond the burst limit are rejected. For `APIs` and login pages, `nodelay` is generally preferred for a better user experience.

    Example Configuration:

    ```
    http {

        # Define a 10MB zone for login attempts.
        # Rate: 1 request per second average.
        limit_req_zone    $binary_remote_addr zone=login_limit:10m rate=1r/s;

        server {

            # NO global rate limit here!

            location / {
                # Normal traffic, no rate limit
            }

            # Apply a strict rate limit ONLY to the login endpoint
            location /login {

                # Use the 'login_limit' zone.
                # Allow a burst of 5 requests, then enforce the 1r/s limit.
                # 'nodelay' ensures a user can quickly resubmit a form without being artificially slowed down.
                limit_req    zone=login_limit burst=5 nodelay;

                # ... other settings ...
            }
        }
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.2.5'
  tag cis_rid:               '5.2.5'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-050205r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  conf = nginx_conf(input('nginx_conf_path'))
  has_zone = !Array(nginx_http_values(conf, 'limit_req_zone')).empty?
  applied = !Array(nginx_http_values(conf, 'limit_req')).empty? ||
            conf.http.servers.any? { |s| !Array(s.params['limit_req']).empty? } ||
            conf.http.servers.flat_map(&:locations).any? { |l| !Array(l.params['limit_req']).empty? }

  describe 'http.limit_req_zone declared (CIS 5.2.5)' do
    subject { has_zone }
    it { should eq true }
  end

  describe 'limit_req applied at http / server / location level (CIS 5.2.5)' do
    subject { applied }
    it { should eq true }
  end
end
