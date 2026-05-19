# encoding: UTF-8

control 'C-2.1.1' do
  title 'Ensure only required dynamic modules are loaded'
  desc  "
    NGINX functionality is provided by modules. These modules are either compiled statically into the NGINX binary or loaded dynamically at runtime via the `load_module` directive.

    - Static Modules: These are fixed at compile time. When using official pre-built packages (e.g., from nginx.org or OS vendors), a standard set of modules is included and cannot be removed without recompiling NGINX.
    - Dynamic Modules: These are separate `.so` files that can be loaded on demand. To reduce the attack surface and complexity, only strictly required dynamic modules should be loaded. Additionally, administrators should be aware of the active static modules to avoid configuring unused features unintentionally.

    Minimizing the loaded code reduces the potential attack surface. While static modules in pre-built packages cannot be removed, ensuring that no unnecessary dynamic modules are loaded prevents the execution of unneeded code. Furthermore, understanding which static modules are present helps administrators avoid enabling risky features (like `autoindex` or `stub_status`) in the configuration if they are not needed.
  "
  desc  'rationale', "
    NGINX functionality is provided by modules. These modules are either compiled statically into the NGINX binary or loaded dynamically at runtime via the `load_module` directive.

    - Static Modules: These are fixed at compile time. When using official pre-built packages (e.g., from nginx.org or OS vendors), a standard set of modules is included and cannot be removed without recompiling NGINX.
    - Dynamic Modules: These are separate `.so` files that can be loaded on demand. To reduce the attack surface and complexity, only strictly required dynamic modules should be loaded. Additionally, administrators should be aware of the active static modules to avoid configuring unused features unintentionally.

    Minimizing the loaded code reduces the potential attack surface. While static modules in pre-built packages cannot be removed, ensuring that no unnecessary dynamic modules are loaded prevents the execution of unneeded code. Furthermore, understanding which static modules are present helps administrators avoid enabling risky features (like `autoindex` or `stub_status`) in the configuration if they are not needed.
  "
  desc  'check', "
    1. Audit Dynamic Modules (Actionable):

    Run the following command to check for actively loaded dynamic modules:
    ```
    nginx -T 2>/dev/null | grep \"load_module\"
    ```
    Evaluation:

    - If the output is empty, no dynamic modules are loaded (PASS).
    - If output exists (e.g., `load_module modules/ngx_http_geoip_module.so;`), verify that each listed module is required for the application's business logic.

    2. Audit Static Modules (Informational):

    Run the following command to list all modules compiled into the binary:
    ```
    nginx -V 2>&1 | grep -oEi '\\-\\-(with|without)-[^ ]*'
    ```
    Evaluation:

    Review the `--with-`... flags to understand the server's capabilities. Ensure that risky modules present in the build (e.g., `http_stub_status_module`) are not enabled in any `server` or `location` block unless authorized.
  "
  desc  'fix', "
    For Dynamic Modules:

    Open the main configuration file (`/etc/nginx/nginx.conf`) or the relevant include file (e.g., in `/etc/nginx/modules-enabled/`). Comment out or remove the `load_module` directive for any module that is not strictly necessary.

    For Static Modules:

    Since static modules cannot be removed from pre-built packages, ensure their directives are not used in your configuration. If a specific static module poses a critical risk to your environment, you must switch to a custom build or a different package flavor that excludes it.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_number:            '2.1.1'
  tag cis_rid:               '2.1.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-020101r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  allowlist = Array(input('nginx_authorized_dynamic_modules'))
  if allowlist.empty?
    describe 'NGINX dynamic modules loaded' do
      skip 'Requires manual review and attestation provided for this control (set `nginx_authorized_dynamic_modules` input to enable automated load_module enforcement; empty default means operator attests per workload)'
    end
  else
    loaded = Array(nginx_conf(input('nginx_conf_path')).params['load_module']).map { |args| args.first.to_s }
    describe 'NGINX load_module directives outside nginx_authorized_dynamic_modules allowlist' do
      subject { loaded.reject { |m| allowlist.include?(m) } }
      it { should be_empty }
    end
  end
end
