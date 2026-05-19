# encoding: UTF-8

control 'C-1.2.1' do
  title 'Ensure package manager repositories are properly configured'
  desc  "
    Package repositories must be trustworthy, properly configured, and maintained to ensure the system receives timely security patches, bug fixes, and support for modern protocols. While Operating System (OS) vendors provide NGINX packages, these versions are often frozen at older release points (\"stable\" but stale). Access to critical modern features like HTTP/3 (QUIC) and the latest TLS updates typically requires using the official repositories maintained by NGINX/F5.

    If a system's package manager repositories are misconfigured or outdated, critical security patches may not be applied in a timely manner. Furthermore, relying solely on default OS repositories often restricts the web server to legacy versions that lack support for modern security standards (e.g., HTTP/3). Using the official nginx.org repositories ensures access to the latest stable and mainline versions directly from the source, reducing the risk of running obsolete software. Conversely, adding untrusted third-party repositories can introduce compromised software or dependency conflicts.
  "
  desc  'rationale', "
    Package repositories must be trustworthy, properly configured, and maintained to ensure the system receives timely security patches, bug fixes, and support for modern protocols. While Operating System (OS) vendors provide NGINX packages, these versions are often frozen at older release points (\"stable\" but stale). Access to critical modern features like HTTP/3 (QUIC) and the latest TLS updates typically requires using the official repositories maintained by NGINX/F5.

    If a system's package manager repositories are misconfigured or outdated, critical security patches may not be applied in a timely manner. Furthermore, relying solely on default OS repositories often restricts the web server to legacy versions that lack support for modern security standards (e.g., HTTP/3). Using the official nginx.org repositories ensures access to the latest stable and mainline versions directly from the source, reducing the risk of running obsolete software. Conversely, adding untrusted third-party repositories can introduce compromised software or dependency conflicts.
  "
  desc  'check', "
    To verify that package manager repositories are configured correctly and point to a trusted source (either the OS vendor or official NGINX), run the following commands:

    Red Hat / Rocky-Linux:
    ```
    dnf repolist -v | grep -i nginx
    ```

    Debian / Ubuntu:
    ```
    apt-cache policy nginx
    ```
    Evaluation:

    - Verify that the repository URL points to a trusted domain (e.g., nginx.org, rhel..., ubuntu...).
    - Ensure that the repository is enabled.
    - Check that no unknown or untrusted third-party repositories are configured for NGINX.
  "
  desc  'fix', "
    Configure your package manager to use a trusted repository that meets your version requirements.

    To enable the official NGINX repository (Recommended for HTTP/3 support):
    Follow the instructions at [nginx.org/en/linux_packages.html](https://nginx.org/en/linux_packages.html) for your specific distribution. This typically involves adding the NGINX signing key and creating a repository configuration file.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001028', 'CCI-001225']
  tag cis_number:            '1.2.1'
  tag cis_rid:               '1.2.1'
  tag cis_benchmark:         'CIS NGINX Benchmark v3.0.0'
  tag cis_rule_id:           'SV-010201r1_rule'
  tag cis_version:           '3.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip 'Requires manual review and attestation provided for this control (package-manager repository configuration is a container-image bake-time concern (or a host provisioning concern) — not something the running NGINX workload expresses; operators attest from their image-build pipeline)'
  end
end
