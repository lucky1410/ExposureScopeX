# ExposureScopeX Support Matrix

**Verified against worker image and catalog:** 2026-09-09

Runtime truth is the capability catalog plus online worker heartbeat. Versions
are pinned in `worker/Dockerfile` and should be updated through reviewed builds.

## Bundled executable tools

| Tool | Purpose | Typical targets | Notes |
|---|---|---|---|
| Subfinder, Assetfinder, Amass | Passive/deep discovery | domain, organization, ASN | Provider API keys improve coverage |
| dnsx | DNS resolution | domain, IP, CIDR | Active DNS behavior depends on profile |
| httpx | HTTP liveness/fingerprint | domain, URL, IP, MCP | Not Python `httpx` CLI |
| Naabu, Nmap, Masscan | Port/service discovery | domain, IP, CIDR | Raw network capability and authorization required |
| Katana, gau, Waybackurls | Route/history discovery | domain, URL | Historical sources may require internet access |
| ffuf, Arjun, Nikto | Content/parameter/web baseline | domain, URL | Bounded by profile and timeouts |
| Nuclei | Template validation | web, network, MCP-adjacent | Curated tags; templates use persistent runtime volume |
| sqlmap | SQL injection validation | domain, URL | Guarded active validation, not default autonomous exploitation |
| Gitleaks | Secret detection | repository | Evidence must remain redacted |
| Trivy | CVE, secret, config and SBOM | repository, image, Kubernetes, mobile artifacts | Static analysis scope varies by target |
| Syft, Grype | SBOM and vulnerability correlation | repository, image | Secondary software inventory adapters |
| Prowler | CSPM | cloud account | Credentials and provider permissions required |
| ExposureScopeX MCP Audit | MCP protocol/security checks | MCP HTTP endpoint | Non-destructive baseline/expanded probes |

## Optional and external

| Tool/service | Status | Requirement |
|---|---|---|
| ScoutSuite | Optional adapter | Operator-installed compatible binary; disabled by default |
| Shodan, VirusTotal, Censys and similar OSINT | Conditional API integration | Organization API key and provider availability |
| Slack, Teams, PagerDuty, Jira | Conditional delivery | Valid endpoint/credential and connectivity test |
| Splunk, Elastic, GitHub SARIF | Conditional export | Destination configuration and authorization |
| GreyNoise, NVD | Conditional enrichment | Provider access/rate limits; local records remain authoritative |
| S3-compatible storage | Conditional | Bucket, endpoint, credentials/workload identity and retention policy |

## Manual interoperability, not bundled execution

Burp Suite evidence, Wireshark captures and specialist mobile proxy/device
evidence can be attached through manual investigation/report workflows. Hydra,
John the Ripper and Aircrack-ng are not default platform scanners. Credential
attacks, wireless testing and unrestricted exploitation require isolated lab
workers and explicit product approval.

## Capability failure semantics

- `available`: worker advertised the required binary/version.
- `blocked`: authorization, credential, prerequisite or policy is missing.
- `skipped`: plan intentionally excluded the check.
- `unavailable`: no compatible online worker or provider.
- `inconclusive`: execution occurred but evidence cannot support pass/fail.
- `failed`: planned execution encountered an error.

None of these states except an evidence-backed completed check should be shown
as successful coverage.
