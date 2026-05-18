# NGINX CIS Baseline

InSpec / CINC Auditor profile validating an NGINX deployment against **CIS NGINX Benchmark v3.0.0**.

## Scope

- **Target:** containerized NGINX workloads (e.g. NGINX sidecar containers running inside ECS Fargate tasks) and any NGINX host install.
- **Platform family:** `container`.
- No AWS partition logic, no `inspec-aws` resource pack — all checks use InSpec built-ins (`file`, `nginx_conf`, `processes`, `passwd`, `shadow`, `command`, `package`).

## Running Locally

Prerequisites: Docker. No vendor step required (no external `depends:`).

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1
```

### Targeting a running container (most realistic for containerized NGINX)

```bash
docker run --rm \
  -v "$PWD:/src" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-nginx \
  -t docker://<container-id-or-name> \
  --input-file /src/profiles/cis-nginx/inputs.yml \
  --reporter cli json:/src/hdf.json
```

### Targeting the local host (host-install consumers)

```bash
docker run --rm \
  -v "$PWD:/src" \
  -v /etc/nginx:/etc/nginx:ro \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-nginx \
  --input-file /src/profiles/cis-nginx/inputs.yml \
  --reporter cli json:/src/hdf.json
```

See InSpec's transport docs for alternative targets (`-t ssh://...`, etc.).

## Portability

Four inputs let consumers point the profile at their NGINX without forking. All defaults match the nginx-official container image.

| Input | Default | When to override |
|---|---|---|
| `nginx_conf_path` | `/etc/nginx/nginx.conf` | Custom config path (e.g., scratch image with `/opt/nginx/`). |
| `nginx_service_user` | `nginx` | Distros / images using a different service account (`www-data` on Debian/Ubuntu host installs). |
| `nginx_authorized_ports` | `[80, 443]` | Workload binds additional ports (mgmt 8443, stream-mode TCP, etc.). Anything outside the list fails CIS 2.4.1. |
| `nginx_authorized_dynamic_modules` | `[]` | When non-empty, enables strict CIS 2.1.1 enforcement on `load_module` directives. Empty default = attestation. |

### Example: containerized NGINX (nginx-official image) `inputs.yml`

```yaml
nginx_conf_path: /etc/nginx/nginx.conf
nginx_service_user: nginx
nginx_authorized_ports: [80, 443]
```

### Example: Debian/Ubuntu host install with strict module allowlist

```yaml
nginx_conf_path: /etc/nginx/nginx.conf
nginx_service_user: www-data
nginx_authorized_ports: [80, 443]
nginx_authorized_dynamic_modules:
  - modules/ngx_http_geoip_module.so
  - modules/ngx_stream_module.so
```

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from the XCCDF's DISA CCI identifiers via Heimdall's `CciNistMappingData.ts`. Provenance chain:

```
XCCDF <ident system="http://cyber.mil/cci">CCI-XXXXXX</ident>
    ↓ (lookup in heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts)
NIST 800-53 control (e.g. "AC-2 (3)")
    ↓ (emitted by tools/xccdf_to_inspec/scaffold.py)
tag nist: ['AC-2 (3)']
```

The scaffolder fails loudly if any rule has a CCI not in the map.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/CIS_NGINX_Benchmark_v3.0.0_xccdf.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-nginx \
  --profile-name cis-nginx \
  --profile-title "NGINX CIS Baseline" \
  --supports-platform container --partitions "" --no-inspec-aws
```

Use `--only <cis-number>` to regenerate a single control.

## Status

All 44 controls filled (issue #18). Each control carries a `tag implementation_status:` mapped to OSCAL's native vocabulary — see the [Control Classification Guide](../../docs/dev/Control_Classification_Guide.md) for the 5-bucket taxonomy.

### Coverage distribution

| Type | `implementation_status` | Count |
|---|---|---|
| **Automated** | `implemented` | 36 |
| **Attestation** | `alternative` | 8 |

The 8 attestation controls are: 1.2.1 (package-repo bake-time), 1.2.2 (latest-version bake-time), 2.1.1 (dynamic-module allowlist — conditional on `nginx_authorized_dynamic_modules` input), 4.1.2 (cert trust chain — PKI/ACM concern), 4.1.6 (TLS 1.3 DH params awareness), 4.1.12 (HTTP/3 adoption target), 5.1.1 (IP allow/deny — workload-specific), 5.1.2 (HTTP methods — location-specific).

### Per-section breakdown

| Section | Subject | Controls | Automated | Attestation |
|---|---|---|---|---|
| 1 | Installation | 3 | 1 | 2 |
| 2 | Basic Configuration | 15 | 14 | 1 |
| 3 | Logging | 4 | 4 | 0 |
| 4 | TLS | 12 | 9 | 3 |
| 5 | Request handling | 10 | 8 | 2 |

### `exec_validated` semantics

Every control carries `tag exec_validated: false`. Describe logic is syntactically valid (cinc-auditor `check` passes) but has not been run against a live container target yet. The first container-target exec post-merge will exercise the 36 automated controls; values flip to `true` after that run. Several controls auto-skip with `not-applicable` rationale when:

- TLS is terminated upstream (no `ssl_certificate` directives) — affects most §4 controls.
- NGINX is not acting as a reverse proxy (no `proxy_pass` directives) — affects 3.4, 4.1.9, 4.1.10, 2.5.4.
- The container image strips `/etc/passwd` or `/etc/shadow` (distroless) — affects 2.2.2, 2.2.3.

These not-applicable skips are documented inline in the control body.

## See also

Top-level `README.md` for overall repo state and the sub-issue tracker for per-profile progress.
