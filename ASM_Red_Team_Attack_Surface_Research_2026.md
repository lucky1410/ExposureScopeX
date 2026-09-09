# Attack Surface Monitoring & Red-Team Platform Blueprint
## End-to-End Asset Discovery, Enumeration, Exposure Detection, Pentesting, Attack-Path Analysis, and MCP Security

**Research baseline:** 29 August 2026
**Requested horizon:** September 2026 and forward-looking 2026+ watchlist
**Purpose:** Design a comprehensive attack-surface monitoring and authorized red-team platform that continuously discovers assets, enumerates them, identifies exposures, performs safe active validation, maps attack paths, and incorporates MCP / agentic AI security.

> **Date note:** September 2026 has not started at the time of this research. Accordingly, this document uses the latest verifiable information available through **29 August 2026**, and labels September 2026 items as a watchlist rather than pretending future events are already known. That small distinction is useful because cybersecurity already has enough fiction without inventing dates.

---

# 1. Executive Summary

A modern attack surface is no longer a list of domains and IP addresses.

A realistic enterprise attack surface is a continuously changing graph containing:

- domains, subdomains, DNS zones and records
- public IPv4 and IPv6 ranges
- autonomous systems, prefixes and routing relationships
- TLS certificates and certificate issuances
- websites, virtual hosts, APIs and API versions
- ports, services, protocols and management interfaces
- cloud accounts, subscriptions, projects, regions and resources
- Kubernetes clusters, workloads, ingress, load balancers and control planes
- containers, registries, images and runtime processes
- serverless functions and event-driven endpoints
- SaaS tenants, externally shared resources and OAuth applications
- identity providers, SSO applications, privileged identities and machine identities
- Git repositories, packages, artifacts, CI/CD systems and deployment pipelines
- secrets, tokens, certificates and credentials exposed in code or metadata
- databases, object stores, queues, caches and message brokers
- mobile applications and associated APIs
- IoT and OT devices and their management interfaces
- remote-access services such as VPN, RDP, SSH, VNC, management portals
- third-party, partner and supply-chain dependencies
- AI models, inference endpoints, RAG stores, agent runtimes and tool integrations
- MCP servers, tools, resources, prompts, tasks, MCP Apps and OAuth relationships
- temporary and ephemeral infrastructure that may exist for minutes or hours
- trust relationships and attack paths between all of the above

A serious ASM/red-team platform should therefore answer five questions continuously:

1. **What exists?**
2. **Who owns it and what does it trust?**
3. **What is exposed and what can actually be reached?**
4. **What can be done with the exposed capability?**
5. **If compromised, what can the attacker reach next?**

That leads to the core platform model:

```text
             DISCOVER
                |
                v
          NORMALIZE / DEDUPE
                |
                v
             ENRICH
                |
                v
       ENUMERATE / FINGERPRINT
                |
                v
          SECURITY TESTING
                |
                v
          EXPOSURE CORRELATION
                |
                v
          ATTACK PATH GRAPH
                |
                v
         RISK + CONFIDENCE
                |
                v
        CONTINUOUS MONITORING
                |
                +----> SIEM / SOAR
                +----> Ticketing
                +----> Executive metrics
                +----> Red-team work queue
```

This approach aligns with the direction of modern ASM products. Microsoft Defender EASM describes continuous external inventory, unmanaged resource discovery, multicloud visibility and exposure detection. Mandiant ASM similarly emphasizes recursive discovery, technology/service identification and active validation. Censys uses relationships among domains, certificates, IPs and ASNs to map internet-facing assets. AWS Security Hub now correlates reachability, vulnerabilities, configuration and resource relationships into exposure findings and attack-path graphs. [Microsoft EASM](https://www.microsoft.com/en-in/security/business/cloud-security/microsoft-defender-external-attack-surface-management), [Google Mandiant ASM](https://cloud.google.com/security/products/attack-surface-management), [Censys ASM](https://docs.censys.com/docs/asm-understand-investigate-attack-surface), [AWS Security Hub exposure findings](https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html)

---

# 2. What Attack Surface Management Should Mean in 2026

ASM should be treated as the intersection of:

```text
EASM  = External Attack Surface Management
CAASM = Cyber Asset Attack Surface Management
CTEM  = Continuous Threat Exposure Management
Vulnerability Management
Cloud Security Posture
Identity Security
SaaS Security
API Security
Application Security
Supply Chain Security
AI / Agent Security
Attack Path Management
```

A modern tool should not force these into separate silos. Instead it should create a single asset and relationship graph.

## 2.1 The six layers of attack surface

### Layer A: Identity surface

Who can authenticate, where, with what privileges, and through which trust path?

### Layer B: Network surface

What can be reached from the internet, corporate network, cloud networks or third-party networks?

### Layer C: Application surface

Which web applications, APIs, mobile backends, services and protocols accept untrusted input?

### Layer D: Data surface

Which systems expose sensitive data or can access it indirectly?

### Layer E: Execution surface

Which assets can execute commands, code, containers, workflows, browser actions or privileged automation?

### Layer F: Trust surface

Which external system, SaaS tenant, OAuth application, package, CI runner, agent, MCP server or third party can cause another asset to act?

The most dangerous exposures often appear when several layers intersect.

Example:

```text
Public API
   |
   +--> weak authorization
          |
          +--> cloud role
                 |
                 +--> object storage
                        |
                        +--> sensitive data
```

The API itself may have a medium severity bug. The **attack path** may be critical.

---

# 3. Master Asset Taxonomy

Your scanner should identify at least the following asset classes.

| Asset class | Examples | Primary discovery methods |
|---|---|---|
| Domain | example.com | seed, RDAP, search engines, CT, passive DNS |
| Subdomain | api.example.com | CT, passive DNS, DNS brute-force, crawling |
| IP | 203.0.113.10 | DNS, ASN, BGP, CT, internet datasets |
| IP range | 203.0.113.0/24 | ASN, RDAP, registries, cloud ownership |
| ASN | AS64500 | WHOIS/RDAP/BGP, seed relationships |
| Prefix | IPv4/IPv6 route | BGP, RPKI/route data |
| Certificate | TLS certificate | CT, TLS handshake |
| Web app | portal.example.com | HTTP probing, crawling |
| API | /api/v1 | OpenAPI, traffic, JS, crawling |
| API gateway | Kong, Apigee, AWS API Gateway | headers, CNAMEs, behavior |
| Service | SSH, RDP, LDAP, database | port/service probing |
| Cloud resource | VM, LB, bucket, function | cloud inventory + public discovery |
| Kubernetes | cluster, ingress, service | cloud inventory, DNS, HTTP, APIs |
| Container | image, runtime | cloud inventory, image metadata, SBOM |
| Serverless | Lambda/function/app | cloud inventory, route discovery |
| SaaS | CRM, ticketing, storage | SSO catalogs, DNS, public assets |
| Identity | user, role, app, workload | IAM/IdP APIs, SSO metadata |
| Repository | GitHub/GitLab repo | public OSINT, authenticated connectors |
| Package | npm, PyPI, container image | repo/package registry |
| CI/CD | Actions, pipelines, runners | source/config/API |
| Secret | token, key, cert, credential | secret scanning + validation |
| Database | SQL, NoSQL, search cluster | service fingerprinting + cloud inventory |
| Storage | S3/object/blob/file share | cloud inventory, DNS, application refs |
| Queue/broker | Kafka, RabbitMQ, SQS | inventory, service fingerprinting |
| Mobile app | iOS/Android | app stores, repos, certificate/package analysis |
| IoT/OT | camera, PLC, gateway | network discovery, product fingerprinting |
| Remote access | VPN, Citrix, RDP, SSH | service enumeration, DNS, certs |
| AI model | hosted/open-source model | cloud inventory, SBOM, process discovery |
| Inference endpoint | vLLM, Ollama, TGI etc. | SBOM/process/network |
| AI agent | agent runtime, workflow | application/cloud discovery |
| MCP server | HTTP/stdIO server | endpoint discovery, config, process inventory |
| MCP tool | search, shell, git, browser | MCP protocol discovery |
| MCP resource | file://, URL, database refs | resources/list/read |
| MCP app | sandboxed server-rendered UI | Apps extension discovery |
| Third party | vendor, partner, service | contracts, DNS, OAuth, integrations |
| Physical/edge | gateway, device, appliance | network/site inventory |

Cloud providers themselves are increasingly exposing asset inventory as an explicit security capability. Google Cloud Asset Inventory provides resource search, relationship data, history and IAM-policy analysis. AWS Security Hub now supports actual internet-reachability scanning and exposure correlation. [Google Cloud Asset Inventory](https://docs.cloud.google.com/asset-inventory/docs), [AWS Security Hub Network Scanning](https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/)

---

# 4. Seed-Based Discovery: Start With Anything, Expand Everywhere

The scanner should accept many seed types rather than only domains.

## 4.1 Supported seed types

```text
Domain
FQDN
IP
CIDR
ASN
Company name
Brand name
Organization name
Certificate fingerprint
Certificate subject/SAN
Cloud account/subscription/project
GitHub organization
Repository URL
Package name
Container registry/repository
SaaS tenant
OAuth client/application
Email domain
Mobile package identifier
Known URL
Known API endpoint
MCP endpoint
Known MCP server configuration
```

Censys explicitly supports domains, IP networks and other public-facing assets as seeds and discovers relationships between them. OWASP Amass is designed for external asset discovery and attack-surface mapping using intelligence sources and active DNS enumeration. ProjectDiscovery Subfinder provides passive subdomain enumeration. [Censys seed guidance](https://docs.censys.com/docs/asm-seed-your-attack-surface), [OWASP Amass](https://devguide.owasp.org/en/06-verification/02-tools/02-amass/), [Subfinder](https://docs.projectdiscovery.io/opensource/subfinder/overview)

## 4.2 Recursive expansion

Every discovered object becomes a possible seed for another collector.

Example:

```text
example.com
  |
  +--> CT certificate
  |      |
  |      +--> api.example.com
  |      +--> vpn.example.com
  |
  +--> DNS
  |      |
  |      +--> 198.51.100.10
  |
  +--> MX
  |      |
  |      +--> mail.example.net
  |
  +--> NS
  |
  +--> CNAME
         |
         +--> vendor.cloud.example
```

Then:

```text
IP
  |
  +--> PTR
  +--> TLS certificate
  +--> open ports
  +--> HTTP virtual hosts
  +--> service fingerprints
```

And:

```text
repository
  |
  +--> deployment files
  +--> Dockerfile
  +--> domains
  +--> cloud identifiers
  +--> API endpoints
  +--> MCP config
  +--> secrets
  +--> package manifests
```

This is how the scanner becomes an attack-surface graph rather than a collection of scripts.

---

# 5. Domain and DNS Attack Surface

## Discover

Use:

- certificate transparency
- passive DNS
- authoritative DNS records
- zone transfers where explicitly authorized
- DNS wordlists / permutation generation
- search engines
- public repositories
- JS and HTML references
- email headers and public documents where authorized
- cloud CNAME patterns
- MX, NS, TXT and SRV records
- DNS history
- reverse DNS
- wildcard detection

Certificate Transparency is particularly valuable because CT logs provide publicly auditable records of TLS certificates and allow organizations to detect unexpected certificates. [RFC 9162](https://www.rfc-editor.org/info/rfc9162)

## Enumerate

For each domain collect:

```text
A
AAAA
CNAME
MX
NS
SOA
TXT
CAA
SRV
HTTPS/SVCB
DS/DNSKEY where relevant
PTR relationships
```

Also identify:

```text
Wildcard DNS
Dangling CNAME
Dangling NS
Expired domains
Subdomain takeover indicators
Unexpected name servers
Unexpected registrars
DNSSEC state
CAA policy
Email security controls
```

## Test

### DNS security

```text
Zone transfer exposure
Open recursion
Authoritative-server exposure
DNSSEC configuration
Dangling records
Wildcard abuse
Subdomain takeover
CNAME to decommissioned provider
Unexpected external nameservers
TXT record leakage
Sensitive information in TXT
Mail routing anomalies
SPF overly permissive policy
DMARC policy weakness
DKIM configuration drift
```

### DNS rebinding

Test applications that validate a hostname before connecting. The important pattern is:

```text
hostname validation
    ↓
DNS resolution
    ↓
connection
```

The scanner should identify whether validation and connection use the same resolved address and whether redirects or DNS changes can alter the destination.

---

# 6. Certificate and TLS Attack Surface

Certificates are both security controls and discovery sources.

## Discover

```text
CT logs
TLS handshakes
Certificate SANs
Certificate subjects
Certificate fingerprints
OCSP / revocation metadata
Public scan datasets
```

Censys explicitly uses certificates observed during TLS handshakes and CT logs to discover services and previously unknown assets. [Censys certificates](https://docs.censys.com/docs/asm-certificate-assets)

## Monitor

```text
New certificate issued
Certificate for unknown host
Unexpected wildcard
Unexpected CA
Certificate nearing expiry
Certificate mismatch
SAN drift
Certificate used on new IP
Private-key reuse indicators
TLS version drift
Weak cipher drift
HTTP/3 / QUIC exposure
```

## Test

```text
TLS version support
Weak protocol versions
Cipher configuration
Certificate chain
Hostname validation
SNI behavior
ALPN behavior
HTTP/2
HTTP/3
HSTS
OCSP stapling
Redirect behavior
TLS on nonstandard ports
Certificate impersonation / organization mismatch
```

A particularly useful correlation is:

```text
new certificate
   + unknown IP
   + recognizable corporate name
   = probable new/rogue asset
```

---

# 7. IP, ASN, Prefix, and Routing Surface

## Discover

```text
RDAP/WHOIS
ASN ownership
BGP prefixes
RPKI data
Reverse DNS
CT
Cloud provider ranges
Historical IP relationships
Passive DNS
Internet measurement platforms
```

## Enumerate

For each IP:

```text
IPv4/IPv6
ASN
prefix
geolocation
provider
PTR
open ports
TLS
HTTP virtual hosts
certificates
observed protocols
```

## Test

```text
unexpected services
management ports
IPv6-only exposures
IPv6 parity gaps
firewall inconsistencies
certificate-host mismatch
service exposure on alternate IPs
shadow IPs not present in CMDB
orphaned cloud addresses
```

### IPv6 deserves first-class treatment

Do not simply scan IPv4 and call the network complete.

Explicitly look for:

```text
AAAA records
IPv6 prefixes
dual-stack load balancers
IPv6-only services
IPv6 firewall policy differences
IPv6 ACL gaps
link-local exposure mistakes
IPv4-mapped addresses
NAT64 behavior
```

---

# 8. Port and Service Enumeration

The scanner should perform layered probing.

```text
Stage 1: DNS resolution
Stage 2: fast port discovery
Stage 3: protocol identification
Stage 4: banner/version detection
Stage 5: application fingerprinting
Stage 6: targeted vulnerability checks
```

Useful technology patterns include the ProjectDiscovery ecosystem:

- Subfinder for passive subdomain discovery
- httpx for HTTP probing and metadata collection
- Naabu for network/port discovery
- Nuclei for template-driven vulnerability detection
- Katana for crawling
- TLS probing and service metadata collection

ProjectDiscovery's current Nuclei engine supports HTTP, DNS, TCP, SSL, WebSocket, headless, JavaScript, file and workflow-based checks, and its `uncover` integrations can query external internet datasets. [ProjectDiscovery docs](https://docs.projectdiscovery.io/quickstart), [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/overview)

## Service categories

```text
Web
DNS
SMTP
IMAP/POP
SSH
FTP/SFTP
RDP
SMB
LDAP
Kerberos
WinRM
VNC
Databases
Redis
MongoDB
Elasticsearch/OpenSearch
Kafka
RabbitMQ
Docker API
Kubernetes APIs
Cloud metadata proxies
VPN gateways
Citrix / remote workspace
Git services
Artifact registries
Monitoring systems
Admin consoles
CI/CD interfaces
Message queues
```

## High-value service detection

Flag especially:

```text
Unauthenticated admin interfaces
Remote management interfaces
Development/debug ports
Metrics endpoints
Health endpoints leaking internals
Database ports on internet
Container APIs
Kubernetes control-plane exposure
CI runners
Artifact repositories
Search clusters
Message brokers
Remote support systems
```

MITRE ATT&CK explicitly treats external remote services as an initial-access surface and includes VPN, Citrix, WinRM, VNC, Docker/Kubernetes management interfaces and other remote services. [MITRE T1133](https://attack.mitre.org/techniques/T1133/), [MITRE T1021](https://attack.mitre.org/techniques/T1021/)

---

# 9. Web Application Enumeration

OWASP's current WSTG attack-surface guidance says web attack-surface identification should include applications, domains, virtual hosts, DNS, subdomains, non-standard ports, certificates and CT logs. The WSTG also emphasizes identifying application entry points and mapping execution paths. [OWASP WSTG Attack Surface Identification](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Attack_Surface_Identification), [OWASP WSTG Entry Points](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points)

## Enumerate

```text
HTTP/HTTPS
Virtual hosts
Paths
Parameters
Forms
Headers
Cookies
Methods
Uploads
WebSockets
SSE
GraphQL
gRPC-Web
Webhooks
OpenAPI/Swagger
robots.txt
sitemap.xml
well-known endpoints
security.txt
source maps
JavaScript
static assets
admin paths
debug endpoints
health endpoints
metrics endpoints
```

## Technology fingerprinting

Identify:

```text
Server
Framework
Language
CMS
JavaScript frameworks
UI libraries
API gateways
CDN
WAF
Reverse proxy
Authentication provider
Cloud platform
Container platform
Monitoring
Feature flags
Version hints
```

But distinguish:

```text
observed version
claimed version
inferred version
vulnerable version
```

Never treat a banner alone as proof of vulnerability.

## Web tests

### Authentication

```text
Missing authentication
Weak authentication boundary
Authentication method downgrade
Session handling
Cookie flags
Token handling
Logout behavior
Password reset
MFA enforcement indicators
SSO misconfiguration
```

### Authorization

```text
BOLA / IDOR
Broken function-level authorization
Property-level authorization
Tenant isolation
Role escalation
Horizontal access
Vertical access
Method confusion
Version-specific access
Hidden endpoint access
```

OWASP API Security identifies BOLA, broken authentication, property/function authorization, unrestricted resource consumption, sensitive business flows, SSRF, security misconfiguration, inventory management and unsafe API consumption among the major API risks. [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

### Input handling

```text
SQL injection
NoSQL injection
Command injection
Template injection
Path traversal
File inclusion
SSRF
Open redirect
Header injection
Host-header issues
Request smuggling indicators
Deserialization
XML parser issues
XXE indicators
Prototype pollution
Expression language injection
```

Active exploit verification should prefer non-destructive canaries and OOB correlation where possible. Nuclei supports OOB testing via interactsh-style callbacks. [Nuclei OOB testing](https://docs.projectdiscovery.io/templates/reference/oob-testing)

---

# 10. API Attack Surface

API inventory deserves its own engine because APIs are commonly under-documented and versioned.

## Discover APIs from

```text
OpenAPI/Swagger
GraphQL introspection where authorized
Postman collections
JavaScript bundles
Mobile apps
Reverse proxy routes
API gateway config
DNS naming patterns
Source repositories
SDKs
Traffic observations
Error messages
Documentation portals
well-known paths
```

## Track

```text
API host
API base path
version
endpoint
method
parameter
schema
authentication
authorization
owner
environment
last seen
public/private
```

## Detect inventory drift

```text
Documented endpoint != observed endpoint
Old API version still exposed
Debug endpoint exposed
Test endpoint exposed
Shadow API
Unused endpoint
Public API with internal assumptions
Stale OAuth scopes
```

## Test matrix

```text
Anonymous
Authenticated low privilege
Authenticated normal user
Admin
Tenant A
Tenant B
Service account
Expired token
Wrong audience
Wrong issuer
Wrong scope
```

For APIs, the most important automation is to compare the **same object/function under multiple identities**.

---

# 11. Cloud Attack Surface

Cloud ASM cannot rely on internet scanning alone.

You need two complementary views.

```text
OUTSIDE-IN
What an attacker can discover and reach

INSIDE-OUT
What the cloud control plane says exists
```

Then correlate them.

## AWS

Inventory:

```text
Accounts
Regions
VPCs
Subnets
Route tables
Security groups
NACLs
EC2
ECS
EKS
Lambda
ALB/NLB
API Gateway
CloudFront
S3
RDS
DynamoDB
ECR
EFS
SQS
SNS
Secrets Manager
IAM
KMS
OpenSearch
Bedrock
AgentCore
SageMaker
```

IAM Access Analyzer supports external-access analysis for resources including S3, IAM roles, KMS keys, Lambda, SQS, Secrets Manager, SNS, snapshots, ECR, EFS and DynamoDB. [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html)

AWS Security Hub now performs actual public reachability scanning for resources across AWS and Azure and correlates that with other security signals. [AWS Network Scanning](https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/)

## Azure

Inventory:

```text
Subscriptions
Resource groups
VMs
VMSS
AKS
App Service
Functions
Container Apps
Storage accounts
SQL
Cosmos DB
Front Door
Application Gateway
API Management
Key Vault
Managed identities
Entra applications
Public IPs
Private endpoints
```

Azure Resource Graph is intended for large-scale resource exploration and governance across subscriptions. [Azure Resource Graph](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)

## Google Cloud

Inventory:

```text
Organizations
Folders
Projects
VPCs
Compute Engine
GKE
Cloud Run
Cloud Functions
Load Balancers
Cloud Storage
Cloud SQL
BigQuery
Pub/Sub
Artifact Registry
Secret Manager
IAM
Service accounts
Vertex AI
```

Google Cloud Asset Inventory supports resource search, history, relationships, IAM-policy search and change monitoring. [Google Cloud Asset Inventory](https://docs.cloud.google.com/asset-inventory/docs)

## Cloud tests

```text
Public IP
Public load balancer
Public bucket
Public database
Public snapshot
Public registry
Public function endpoint
Public API endpoint
Metadata exposure
Overly broad security group
0.0.0.0/0 management access
::/0 management access
Overly broad IAM
Unused privileged role
Cross-account trust
Cross-tenant trust
Weak condition keys
Unrestricted service principals
Public OAuth application
Leaked credentials
```

---

# 12. Container and Kubernetes Attack Surface

## Discover

```text
container registries
image tags
image digests
running containers
Kubernetes clusters
API servers
ingress
load balancers
services
node ports
host networking
privileged pods
service accounts
RBAC roles
secrets/configmaps
admission controllers
operators
Helm charts
CRDs
```

## Test

```text
Public Kubernetes API
Public kubelet
Public dashboards
Unauthenticated metrics
NodePort exposure
LoadBalancer exposure
Privileged workload
HostPath
HostNetwork
HostPID
host namespace access
wildcard RBAC
cluster-admin bindings
service-account token exposure
sensitive Secret exposure
ingress auth bypass
network-policy gaps
container escape indicators
registry exposure
unsigned/untrusted images
image provenance gaps
```

OWASP's Docker guidance recommends constrained capabilities, least privilege, resource limits and monitoring of unusual process, filesystem and network activity. [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## Container supply chain

Correlate:

```text
image
→ digest
→ SBOM
→ package
→ CVE
→ runtime instance
→ public endpoint
→ identity
```

This is far more useful than simply saying “image contains CVE-X”.

---

# 13. Software Supply Chain Attack Surface

Inventory should include:

```text
Git repositories
Branches
Tags
Releases
Package registries
Container images
Build systems
CI/CD runners
GitHub Actions
GitLab CI
Build artifacts
Deployment manifests
Terraform
CloudFormation
Helm
Dockerfiles
Dependencies
SBOMs
Provenance attestations
Signing keys
Package publishers
```

SLSA 1.2 is the current approved SLSA specification and emphasizes verifiable provenance that tracks where and how artifacts were produced. [SLSA 1.2](https://slsa.dev/spec/v1.2/)

## Tests

```text
Dependency vulnerabilities
Known exploited dependency
Typosquat indicators
Unpinned dependencies
Mutable tags
Unsigned images
Missing provenance
Unexpected build source
Untrusted CI runner
Third-party action abuse
Workflow injection
Secrets in CI
Artifact overwrite
Release provenance mismatch
Package publisher change
New dependency added
Dependency removed unexpectedly
```

OSV provides an API and scanner that can query vulnerabilities by package/version or commit and scan SBOMs and lockfiles. [OSV](https://osv.dev/)

---

# 14. Secrets and Credential Attack Surface

Secret discovery should cover:

```text
Git history
Current repository contents
Issues
Pull requests
Actions logs
CI variables
Container layers
Docker images
Build artifacts
npm packages
Python packages
Terraform state
Kubernetes manifests
Helm values
Cloud metadata
Logs
Chat exports where authorized
Public documentation
Source maps
Mobile binaries
Browser storage
```

GitHub's current security tooling includes secret scanning and push protection, with pattern-based and AI-assisted detection. [GitHub secret security](https://docs.github.com/en/code-security/reference/secret-security), [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

## Do not stop at regex

For each candidate secret:

```text
pattern match
    ↓
provider identification
    ↓
format validation
    ↓
safe liveness check
    ↓
privilege / scope classification
    ↓
owner identification
    ↓
rotation status
```

The scanner should avoid destructive use of discovered credentials. Prefer metadata/liveness checks and explicit authorization for any deeper validation.

---

# 15. Identity and SaaS Attack Surface

This is one of the most important expansions beyond network ASM.

## Inventory

```text
Identity provider
Users
Groups
Roles
Service accounts
Workload identities
OAuth applications
Enterprise applications
API clients
SSO integrations
SCIM connectors
Privileged accounts
Guest users
External identities
Machine-to-machine identities
Long-lived tokens
Certificates
```

## SaaS inventory

Discover via:

```text
SSO application catalog
DNS
OAuth grants
browser/application telemetry
public tenant URLs
company naming patterns
email domains
repositories
vendor integrations
```

## Test

```text
Unknown SaaS application
Public tenant
Weak SSO configuration
Missing MFA indicators
Overbroad OAuth scopes
Unused OAuth grants
Cross-tenant access
Public sharing
Anonymous links
Guest accounts
Orphaned applications
Stale service principals
Secrets in SaaS configuration
Third-party integration trust
```

The scanner should explicitly model:

```text
User → SaaS App → OAuth Token → API → Cloud Resource
```

because the security problem may be the chain, not the individual application.

---

# 16. Email and Messaging Attack Surface

Discover:

```text
MX hosts
Mail providers
SMTP gateways
Secure mail portals
Webmail
DMARC
SPF
DKIM
Inbound relays
Outbound relays
Email security gateways
Phishing/reporting portals
```

Test:

```text
SPF overly broad
DMARC missing/weak
DKIM problems
Open relay indicators
SMTP auth exposure
Legacy protocols
TLS weaknesses
Mail gateway version exposure
Webmail authentication boundary
Attachment scanning behavior
```

Also look for email-driven trust paths:

```text
email → workflow
email → ticket
email → SOAR
email → automation
email → MCP tool
```

These can turn message content into command input.

---

# 17. Mobile Attack Surface

Mobile ASM should connect:

```text
App Store / Play Store
     ↓
Package identifier
     ↓
Version
     ↓
Certificate
     ↓
API endpoints
     ↓
Cloud services
     ↓
OAuth clients
```

## Discover

```text
iOS bundle IDs
Android package IDs
application versions
developer/publisher
embedded domains
embedded URLs
API base URLs
Firebase configuration
S3/blob references
OAuth client IDs
API keys
certificate pins
deep links
universal links
intent filters
```

## Test

Use OWASP MASVS/MASTG as the control framework. MASVS covers storage, cryptography, authentication, authorization, network communication, platform interaction, code quality and resilience against reverse engineering/tampering. [OWASP MASVS](https://mas.owasp.org/MASVS/)

---

# 18. IoT and OT Attack Surface

Treat this as a distinct safety-sensitive scan mode.

## Discover

```text
SNMP
mDNS
UPnP
ONVIF
industrial protocols
vendor discovery protocols
DHCP fingerprints
MAC/OUI
serial-to-IP gateways
management portals
VPN access
remote vendor access
```

## Inventory

```text
device
vendor
model
firmware
serial
management interface
protocols
network zone
physical owner
vendor owner
```

## Test

Prefer safe fingerprinting and configuration checks first.

```text
unauthenticated management
weak authentication indicators
exposed admin portals
old firmware
insecure protocols
remote access exposure
flat network placement
SNMP community exposure
vendor cloud trust
```

OWASP's IoT Security Verification Standard provides a dedicated verification framework and includes 156 security requirements in the official 1.0 release. [OWASP ISVS](https://owasp.org/IoT-Security-Verification-Standard-ISVS/)

---

# 19. Remote Access and Management Surface

Continuously monitor:

```text
VPN
ZTNA
RDP
SSH
VNC
WinRM
Citrix
remote support tools
virtual desktop portals
hypervisor management
backup management
network-device management
Kubernetes management
cloud consoles
```

## Risk signals

```text
public admin interface
missing MFA indicators
old software
legacy protocol
single-factor access
broad source network
anonymous access
unexpected geography/provider
```

MITRE ATT&CK explicitly calls external remote services an initial-access surface. [MITRE T1133](https://attack.mitre.org/techniques/T1133/)

---

# 20. Webhooks and Event-Driven Attack Surface

Modern applications expose a massive invisible surface through webhooks.

Discover:

```text
webhook endpoints
callback URLs
event subscriptions
SNS/SQS callbacks
GitHub webhooks
Stripe-like callbacks
OAuth callbacks
CI callbacks
automation triggers
MCP task/event callbacks
```

Test:

```text
unauthenticated callback
signature validation
replay protection
timestamp validation
source validation
SSRF through callback destination
redirect behavior
payload size limits
schema validation
idempotency
event ordering
duplicate delivery
```

A webhook is essentially an API where the attacker controls the timing and often the payload. Treat it like one.

---

# 21. Browser and Client-Side Attack Surface

Discover:

```text
JavaScript
source maps
browser extensions
service workers
WebSockets
WebRTC
postMessage
OAuth redirects
deep links
custom URL schemes
file downloads
browser-based admin tools
```

Test:

```text
DOM XSS
CSP gaps
postMessage origin checks
open redirects
unsafe downloads
extension permissions
local storage secrets
service worker scope
mixed content
CORS
WebSocket origin/auth
```

---

# 22. AI and Agentic Attack Surface

This should be a first-class ASM category in 2026.

OWASP released a 2026 Top 10 for Agentic Applications and a dedicated 2026 red-team taxonomy. AWS Security Hub now catalogs managed and self-hosted AI workloads, including models, inference endpoints and agents, and correlates them with software inventory and DNS signals. [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [OWASP Red Teaming Taxonomy](https://genai.owasp.org/resource/solutions-landscape-red-teaming-taxonomy/), [AWS AI Inventory](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-ai-inventory.html)

## AI assets to discover

```text
LLM endpoints
Model APIs
Self-hosted models
Inference servers
AI gateways
Agents
Agent frameworks
RAG pipelines
Vector databases
Embedding services
Prompt stores
System prompts
Tool registries
Function calling interfaces
MCP servers
MCP clients
MCP Apps
AI plugins
AI workflow automations
Evaluation systems
Training/fine-tuning jobs
Model artifacts
Model registries
AI-related cloud identities
```

AWS currently detects self-hosted models and inference servers through SBOM and related signals, including software such as Ollama, vLLM, Triton, TGI, SGLang, llama.cpp and others. [AWS AI Inventory](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-ai-inventory.html)

## Test categories

```text
Prompt injection
Sensitive information disclosure
Excessive agency
Improper output handling
System prompt exposure
Tool authorization
Agent identity
Agent privilege escalation
RAG poisoning
Vector-store isolation
Model supply chain
Training/fine-tuning data poisoning
Unbounded model consumption
Unsafe tool chaining
Cross-agent trust
External tool trust
Browser automation abuse
```

OWASP's current LLM guidance includes prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation and unbounded consumption. [OWASP LLM Top 10 2025/2026](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

A key architectural principle is:

```text
AI asset ≠ application asset

AI asset + tools + identity + data + egress
                        = attack path
```

---

# 23. MCP Attack Surface Module

Model Context Protocol (MCP) should be treated as an application, identity, data, execution, and trust surface rather than as a JSON-RPC protocol alone. The July 28, 2026 protocol release materially expands the testing surface with stateless operation, `server/discover`, header-based routing, Multi Round-Trip Requests (MRTR), cacheability, Tasks, extensions, MCP Apps, and stronger OAuth requirements. The scanner should therefore test not only protocol correctness but also identity binding, state transitions, capability authorization, downstream sinks, agent behavior, and cross-server attack paths.

**Research baseline:** 29 August 2026. September 2026 is treated as a future watchlist, not as a source of fabricated post-August facts.

## 23.1 Basic MCP architecture

```text
AI Host / Agent
      |
      v
   MCP Client
      |
      +---------------------------+
      |                           |
      v                           v
Streamable HTTP / HTTP        stdio / local
      |
      v
   MCP Server
      |
      +-- discovery
      +-- tools
      +-- resources
      +-- resource templates
      +-- prompts
      +-- tasks
      +-- MRTR
      +-- extensions / MCP Apps
      |
      v
Downstream execution and data plane
  +-- OS / shell
  +-- filesystem
  +-- git / CI/CD
  +-- cloud APIs
  +-- Kubernetes
  +-- databases
  +-- browsers
  +-- HTTP services
  +-- SaaS / OAuth
```

The scanner should build an **MCP security graph** linking:

```text
identity → request → state → primitive → parameter → sink → downstream identity → data / execution
```

This graph is more important than a flat list of endpoint findings because many serious MCP failures are combinations of individually legitimate capabilities.

## 23.2 Existing coverage baseline

The current module already performs or reviews:

```text
server/discover
legacy initialize / notifications/initialized fallback
ping
tools/list + pagination
resources/list + pagination
resources/templates/list + pagination
prompts/list + pagination
OAuth protected-resource discovery
path-scoped OAuth discovery
unauthenticated initialize / tools/list probes
Origin / CORS / simple cross-site POST behavior
unsupported methods
invalid JSON-RPC versions
malformed JSON
unknown tool/resource/prompt/task targets
Mcp-Method vs JSON-RPC method mismatch
task enumeration / rejection probes
session replay review
session DELETE cleanup
metadata poisoning and prompt-injection indicators
dangerous capability analysis
read + egress/execute capability chains
unbounded strings
sensitive parameter names
path-like inputs
SSRF-like inputs
loose schemas / additionalProperties
external $ref
sensitive filesystem resources
TLS / remote endpoint checks
redirect checks
cache hints
OAuth discovery hints
```

That remains the **baseline layer**. The canonical specification below adds the missing behavioral, stateful, identity, semantic, supply-chain, and concurrency coverage.

# 24. MCP Canonical Test Specification

## 24.1 Standard record schema

Every scanner test should be represented internally with the following fields, regardless of whether the final UI shows all of them:

| Field | Meaning |
|---|---|
| ID | Stable test identifier; never recycle IDs |
| Objective | Security property being evaluated |
| Preconditions | What must exist before execution |
| Discovery | How the candidate target/sink is identified |
| Passive test | Non-invasive observation or static analysis |
| Active-safe test | Controlled test that should not modify production data |
| Deep-pentest test | Stronger validation for an authorized sandbox/staging target |
| Evidence | Exact request, response, metadata, trace, or behavioral artifact to retain |
| Detection logic | Condition that creates the finding |
| False positives | Common benign explanations |
| Severity | Default severity before environmental adjustment |
| CWE | Useful weakness classification |
| MITRE | Suggested ATT&CK technique where applicable |
| Remediation | Security control expected from the operator |
| Regression | Test that should remain in a future CI/security run |

### Execution safety model

Use three execution modes:

```text
PASSIVE
  Discovery, fingerprinting, source/config analysis, metadata comparison.

ACTIVE-SAFE
  Canary values, non-destructive reads, controlled identities, isolated cache/state,
  bounded concurrency and synthetic destinations.

DEEP-PENTEST
  Authorized staging/lab validation for execution sinks, races, destructive workflow
  states, long-running tasks, browser actions, command execution and exploit chains.
```

Never turn the default ASM scan into an uncontrolled exploit framework. The same scanner should be able to prove a weakness safely and reserve exploit-grade actions for an explicit authorization mode.

---

## 24.2 Discovery and protocol parsing

### MCP-PROTO-001 — Protocol/version downgrade
**Objective:** Detect acceptance of obsolete or weaker protocol behavior when the endpoint advertises modern MCP.

**Preconditions:** A reachable MCP endpoint.

**Discovery:** Probe `server/discover`, protocol headers, and response metadata.

**Passive test:** Record advertised protocol versions and extensions.

**Active-safe test:** Send supported, unsupported, and older protocol identifiers and compare behavior.

**Deep-pentest test:** Attempt controlled downgrade followed by an operation that should require a stronger protocol/security policy.

**Evidence:** Version request/response pairs and any successful privileged operation after downgrade.

**Detection logic:** Older/weaker behavior is accepted when policy requires the modern profile, or security controls disappear after downgrade.

**False positives:** Deliberate backward compatibility with identical security enforcement.

**Severity:** Medium, High if downgrade removes authentication or authorization.

**CWE:** CWE-757.

**MITRE:** T1078 when downgrade enables credential misuse.

**Remediation:** Enforce an explicit minimum protocol/security profile.

**Regression:** Repeat downgrade matrix after every MCP SDK upgrade.

---

### MCP-PROTO-002 — Header/body method desynchronization
**Objective:** Ensure routing/authorization cannot be bypassed by making gateway-visible and backend-visible methods differ.

**Preconditions:** Modern MCP endpoint using `Mcp-Method`.

**Discovery:** Determine whether an intermediary, gateway, or framework routes on MCP headers.

**Passive test:** Compare observed headers and JSON-RPC body fields.

**Active-safe test:** Send a conflicting `Mcp-Method` and JSON-RPC `method` using harmless targets.

**Deep-pentest test:** Place a lower-privilege method in the gateway-visible field and a higher-privilege method in the backend-visible field in a lab.

**Evidence:** HTTP request, gateway response, backend response/log correlation if available.

**Detection logic:** Any mismatch is accepted, normalized inconsistently, or produces different authorization decisions.

**False positives:** Endpoint rejects the request before dispatch.

**Severity:** High to Critical.

**CWE:** CWE-436.

**MITRE:** T1190.

**Remediation:** Canonically parse once and reject inconsistent method/name representations.

**Regression:** Fixed negative test for every method-bearing request.

---

### MCP-PROTO-003 — Duplicate HTTP security headers
**Objective:** Identify parser differentials caused by duplicate security-sensitive headers.

**Preconditions:** HTTP MCP transport.

**Discovery:** Identify security-sensitive headers: `Authorization`, `Content-Type`, `Mcp-Method`, `Mcp-Name`, `Host`, forwarding headers.

**Passive test:** Inspect server/proxy normalization behavior.

**Active-safe test:** Send duplicate headers with equivalent values, then conflicting values using a canary endpoint.

**Deep-pentest test:** Exploit a proxy/backend disagreement where one layer authorizes and another executes differently.

**Evidence:** Raw wire representation and resulting interpretation.

**Detection logic:** Different layers choose different header values or fail open.

**False positives:** Well-defined rejection or deterministic canonicalization.

**Severity:** High where identity/routing can change.

**CWE:** CWE-444.

**MITRE:** T1190.

**Remediation:** Reject ambiguous duplicates at the edge.

**Regression:** Proxy + backend differential test.

---

### MCP-PROTO-004 — Duplicate JSON fields / parser differential
**Objective:** Detect different interpretation of duplicated or case-variant JSON fields.

**Preconditions:** JSON-RPC endpoint.

**Discovery:** Identify parser/framework and whether a gateway performs JSON inspection.

**Passive test:** Review parser configuration and SDK behavior.

**Active-safe test:** Send duplicated `method`, `id`, `jsonrpc`, `params`, and case-variant keys.

**Deep-pentest test:** Create an authorization mismatch between first/last-wins parsing layers in a lab.

**Evidence:** Raw payload and effective server behavior.

**Detection logic:** Ambiguous JSON produces a privileged action or inconsistent interpretation.

**False positives:** Explicit rejection or a documented deterministic rule that applies everywhere.

**Severity:** High if security decisions depend on the duplicated field.

**CWE:** CWE-436 / CWE-20.

**MITRE:** T1190.

**Remediation:** Reject duplicate security-sensitive keys and normalize once.

**Regression:** Parser differential corpus.

---

### MCP-PROTO-005 — Unicode normalization / confusable identifiers
**Objective:** Detect mismatches in tool, method, resource, header, host, or parameter normalization.

**Preconditions:** Unicode-capable endpoint or identifiers.

**Discovery:** Enumerate names and identify normalization paths.

**Passive test:** Compute NFC/NFKC and confusable representations.

**Active-safe test:** Submit harmless confusable variants of method/tool/resource names.

**Deep-pentest test:** Use a lab alias where one layer treats a confusable identifier as privileged.

**Evidence:** Original bytes, normalized forms, and selected target.

**Detection logic:** Security control applies to one representation while dispatch uses another.

**False positives:** Strict ASCII allowlisting.

**Severity:** Medium, High for authorization bypass.

**CWE:** CWE-178.

**MITRE:** T1036.

**Remediation:** Canonicalize identifiers and restrict security-sensitive names to a safe charset.

**Regression:** Confusable corpus.

---

### MCP-PROTO-006 — Encoding and path canonicalization differential
**Objective:** Detect mismatches involving percent-encoding, double encoding, dot segments, separators, and URI normalization.

**Preconditions:** Resource or path-like targets.

**Discovery:** Extract paths/URIs from tools, resources, and templates.

**Passive test:** Compute canonical variants.

**Active-safe test:** Send harmless encoded variants and observe whether they map to different logical objects.

**Deep-pentest test:** Validate traversal only against a dedicated canary directory.

**Evidence:** Input, canonical form, resolved target.

**Detection logic:** Validation occurs before canonicalization or multiple layers resolve differently.

**False positives:** Consistent 4xx rejection.

**Severity:** High where files or privileged resources are reachable.

**CWE:** CWE-22 / CWE-23.

**MITRE:** T1006.

**Remediation:** Canonicalize before validation and before final sink use.

**Regression:** Traversal/canonicalization corpus.

---

## 24.3 Authentication and authorization

### MCP-AUTH-001 — Missing authentication
**Objective:** Detect operations callable without required authentication.

**Preconditions:** Endpoint that is expected to be protected.

**Discovery:** OAuth metadata, `401` responses, gateway configuration, route inventory.

**Passive test:** Compare protected and unprotected methods.

**Active-safe test:** Call discovery/list/read endpoints without credentials.

**Deep-pentest test:** Attempt controlled privileged operations without credentials in a lab.

**Evidence:** Request/response showing operation success.

**Detection logic:** Protected capability succeeds anonymously.

**False positives:** Deliberately public discovery metadata.

**Severity:** High/Critical for privileged capabilities.

**CWE:** CWE-306.

**MITRE:** T1078 / T1190.

**Remediation:** Enforce authentication at the final operation boundary.

**Regression:** Anonymous negative-test suite.

---

### MCP-AUTH-002 — Token audience/resource mismatch
**Objective:** Ensure credentials are bound to the intended protected resource.

**Preconditions:** OAuth/OIDC protected MCP endpoint.

**Discovery:** Authorization-server metadata and token claims/introspection.

**Passive test:** Record expected `aud`, resource indicators, issuer, scope and client binding.

**Active-safe test:** Present a syntactically valid token minted for another resource/scope.

**Deep-pentest test:** Attempt a privileged operation after substituting a token from a sibling service.

**Evidence:** Token claims (redacted) and authorization outcome.

**Detection logic:** Wrong-resource credentials are accepted.

**False positives:** Deliberate shared audience with documented trust.

**Severity:** High/Critical.

**CWE:** CWE-287 / CWE-862.

**MITRE:** T1550.

**Remediation:** Validate issuer, audience/resource, scope and intended client binding.

**Regression:** Cross-service token matrix.

---

### MCP-AUTH-003 — Issuer validation failure
**Objective:** Ensure issuer identity is mandatory and validated.

**Preconditions:** JWT validation or introspection path.

**Discovery:** Determine how issuer is sourced and whether missing claims are accepted.

**Passive test:** Review validation configuration.

**Active-safe test:** Use a test token from an unauthorized issuer or omit issuer where the implementation permits a synthetic introspection response.

**Deep-pentest test:** Validate whether an unintended identity provider can satisfy authentication.

**Evidence:** Issuer, validation decision, and resulting authorization.

**Detection logic:** Token is accepted without a trusted issuer binding.

**False positives:** Explicitly configured multi-issuer trust.

**Severity:** Critical.

**CWE:** CWE-287.

**MITRE:** T1078.

**Remediation:** Require and verify trusted issuer identity.

**Regression:** Multi-issuer negative tests.

---

### MCP-AUTH-004 — Scope/privilege mismatch
**Objective:** Ensure a token cannot invoke capabilities outside its effective scope.

**Preconditions:** Multiple OAuth scopes or roles.

**Discovery:** Map each scope/role to tools, resources, tasks, and administrative operations.

**Passive test:** Build authorization matrix.

**Active-safe test:** Use a low-privilege token against higher-privilege capabilities.

**Deep-pentest test:** Explore aliases, hidden tools, task updates, and resource templates under the lower-privilege identity.

**Evidence:** Token scope and operation result.

**Detection logic:** Authorization is based on authentication only or is inconsistently enforced across methods.

**False positives:** Tool is intentionally public.

**Severity:** High/Critical.

**CWE:** CWE-862.

**MITRE:** T1548 / T1078.

**Remediation:** Authorize each privileged operation at execution time.

**Regression:** Role-by-operation matrix.

---

### MCP-AUTH-005 — Hidden-tool direct invocation / allowlist bypass
**Objective:** Verify that hiding a tool from `tools/list` is not treated as authorization.

**Preconditions:** Tool inventory with disabled/hidden/restricted tools.

**Discovery:** Compare `tools/list`, source/configuration where available, known historical fingerprints, and gateway policy.

**Passive test:** Identify tools omitted from discovery or marked restricted.

**Active-safe test:** Directly call hidden/restricted targets using harmless arguments.

**Deep-pentest test:** Invoke a privileged hidden operation in an isolated environment.

**Evidence:** Tool call and policy decision.

**Detection logic:** Hidden/restricted tool executes for an identity that should not reach it.

**False positives:** Tool truly public but intentionally undiscoverable.

**Severity:** High/Critical.

**CWE:** CWE-862.

**MITRE:** T1190.

**Remediation:** Enforce allowlists at dispatch, not just discovery.

**Regression:** Hidden-tool negative corpus.

---

### MCP-AUTH-006 — Cross-principal operation isolation
**Objective:** Ensure identity A cannot read, update, execute, or cancel state belonging to identity B.

**Preconditions:** Two controlled identities with distinguishable data.

**Discovery:** Identify principal-scoped resources, tasks, caches, subscriptions, and sessions.

**Passive test:** Build principal-to-state map.

**Active-safe test:** A creates/reads data; B attempts the same object with a canary.

**Deep-pentest test:** Interleave A/B operations under concurrency.

**Evidence:** Principal, object identifier, result, and authorization trace.

**Detection logic:** B gains access to A-owned state or vice versa.

**False positives:** Deliberately shared public state.

**Severity:** Critical for confidential or privileged state.

**CWE:** CWE-639 / CWE-862.

**MITRE:** T1210 / T1078.

**Remediation:** Bind object/state ownership to authenticated principal and tenant.

**Regression:** Two-principal isolation suite.

---

## 24.4 Stateless execution, state, and concurrency

### MCP-STATE-001 — Cross-instance state leakage
**Objective:** Detect process/global state that leaks between clients when requests hit different server instances.

**Preconditions:** Load-balanced or horizontally scalable deployment, or reusable server objects.

**Discovery:** Identify instance count, shared transports, caches, connection pools, and process globals.

**Passive test:** Observe correlation IDs, response instance metadata, and stateful variables.

**Active-safe test:** Interleave two principals across repeated requests and compare results.

**Deep-pentest test:** Force routing across multiple instances and race state creation/read operations.

**Evidence:** Client/instance/state correlation timeline.

**Detection logic:** Principal A's state appears in B's response or authorization context changes unexpectedly.

**False positives:** Deliberately shared public state.

**Severity:** Critical.

**CWE:** CWE-200 / CWE-922.

**MITRE:** T1552 when secrets are exposed.

**Remediation:** Make security state explicitly request/identity scoped.

**Regression:** Multi-instance concurrency run.

---

### MCP-STATE-002 — Shared transport/context contamination
**Objective:** Detect reusable transport objects that accidentally retain prior authentication, metadata, or request context.

**Preconditions:** Persistent connections, connection pools, or SDK transport reuse.

**Discovery:** Identify transport reuse and mutable context structures.

**Passive test:** Inspect lifecycle/configuration.

**Active-safe test:** Alternate A/B authentication on one controlled connection/pool.

**Deep-pentest test:** High-concurrency cross-client reuse with distinct privileges.

**Evidence:** Which identity/metadata was applied to each request.

**Detection logic:** Authentication or state from one client affects another.

**False positives:** Intentionally pinned connection identity with documented semantics.

**Severity:** Critical.

**CWE:** CWE-668 / CWE-639.

**MITRE:** T1078.

**Remediation:** Avoid mutable shared security context; bind context to request or principal.

**Regression:** Connection-reuse isolation tests.

---

### MCP-STATE-003 — Request-state replay
**Objective:** Ensure transient protocol state cannot be replayed outside its intended request lifecycle.

**Preconditions:** MRTR or other request-state mechanism.

**Discovery:** Detect `requestState`, continuation tokens, or opaque workflow IDs.

**Passive test:** Record state lifetime and metadata.

**Active-safe test:** Replay the same state after completion using the same identity.

**Deep-pentest test:** Replay it under another identity and after permission changes.

**Evidence:** State ID/hash, timestamps, principal, operation and result.

**Detection logic:** State can be reused when it should be one-time or scoped.

**False positives:** Explicitly reusable state with proper authorization binding.

**Severity:** High/Critical.

**CWE:** CWE-294 / CWE-613.

**MITRE:** T1078.

**Remediation:** Bind state to principal, operation, resource, nonce and expiry as appropriate.

**Regression:** One-time and cross-principal replay cases.

---

### MCP-STATE-004 — Authorization change between rounds
**Objective:** Ensure MRTR/task continuations re-check authorization after identity or policy changes.

**Preconditions:** Multi-step operation and controllable authorization state.

**Discovery:** Identify operations that pause and resume.

**Passive test:** Document auth checks per transition.

**Active-safe test:** Revoke or change a test user's privilege between rounds.

**Deep-pentest test:** Resume the operation after privilege removal in a lab.

**Evidence:** Authorization before round one, after transition, and final action.

**Detection logic:** Privilege revoked before completion is still honored.

**False positives:** Deliberately immutable task authorization documented by design.

**Severity:** High/Critical.

**CWE:** CWE-841 / CWE-862.

**MITRE:** T1098.

**Remediation:** Re-evaluate authorization at every privileged transition.

**Regression:** Privilege-revocation mid-workflow test.

---

### MCP-STATE-005 — Race conditions on identity/state transitions
**Objective:** Detect TOCTOU and concurrent update flaws in MCP state machines.

**Preconditions:** Mutable resources, tasks, approvals, or continuation state.

**Discovery:** Identify operations that read then update security state.

**Passive test:** Inspect locking/transaction semantics when source is available.

**Active-safe test:** Run bounded parallel canary requests against non-destructive objects.

**Deep-pentest test:** Race authorization check against update/cancel/execute in a lab.

**Evidence:** Ordered event timeline and final state.

**Detection logic:** Unauthorized final state or duplicate execution becomes possible through interleaving.

**False positives:** Expected idempotent retries.

**Severity:** High/Critical.

**CWE:** CWE-362 / CWE-367.

**MITRE:** T1190.

**Remediation:** Atomic authorization + state transitions; idempotency controls.

**Regression:** Deterministic race harness.

---

## 24.5 Multi Round-Trip Requests (MRTR)

### MCP-MRTR-001 — Request-state principal binding
**Objective:** Ensure MRTR state is cryptographically or server-side bound to the original principal.

**Preconditions:** MRTR-capable server.

**Discovery:** Detect `input_required`, `requestState`, and retry semantics.

**Passive test:** Record principal/state relationship.

**Active-safe test:** A obtains state; B submits it with a harmless response.

**Deep-pentest test:** Use B to complete a privileged A-initiated workflow in a lab.

**Evidence:** State and principal on both rounds.

**Detection logic:** B can continue A's workflow.

**False positives:** Intentionally shared workflow tokens with independent authorization at final sink.

**Severity:** Critical.

**CWE:** CWE-639 / CWE-294.

**MITRE:** T1078.

**Remediation:** Bind continuation state to principal, client and operation.

**Regression:** Cross-principal MRTR replay.

---

### MCP-MRTR-002 — Tool/resource substitution between MRTR rounds
**Objective:** Prevent changing the target operation while reusing valid continuation state.

**Preconditions:** MRTR workflow that pauses before execution.

**Discovery:** Capture original tool/resource identity.

**Passive test:** Compare target identifiers across rounds.

**Active-safe test:** Attempt to substitute another harmless target.

**Deep-pentest test:** Substitute a privileged target in a sandbox.

**Evidence:** Original target, resumed target, authorization decision.

**Detection logic:** Continuation state authorizes a different target.

**False positives:** State intentionally represents a general workflow with separate final authorization.

**Severity:** High/Critical.

**CWE:** CWE-639.

**MITRE:** T1190.

**Remediation:** Bind state to method/tool/resource and canonical parameters.

**Regression:** Target substitution matrix.

---

### MCP-MRTR-003 — Input-response substitution / type confusion
**Objective:** Ensure responses to requested inputs are associated with the correct request and schema.

**Preconditions:** `inputRequests` / `inputResponses` or equivalent continuation flow.

**Discovery:** Capture input request IDs, names and schema.

**Passive test:** Compare schema and response mapping.

**Active-safe test:** Swap two same-type canary responses.

**Deep-pentest test:** Supply a privilege-relevant value to the wrong field in a lab.

**Evidence:** Input IDs, types, final interpreted values.

**Detection logic:** Values are accepted for the wrong request/field or schema checks differ across rounds.

**False positives:** Schema intentionally allows equivalent fields.

**Severity:** High.

**CWE:** CWE-20 / CWE-843.

**MITRE:** T1190.

**Remediation:** Strongly bind input response to request ID and schema.

**Regression:** Cross-field substitution corpus.

---

### MCP-MRTR-004 — Infinite/recursive MRTR loop
**Objective:** Detect unbounded multi-round workflows that can exhaust resources.

**Preconditions:** MRTR-capable server.

**Discovery:** Observe maximum round handling.

**Passive test:** Record limits/timeouts.

**Active-safe test:** Request a bounded synthetic continuation loop.

**Deep-pentest test:** Run a deliberately capped high-round workflow in a lab.

**Evidence:** Round count, memory/CPU, connection lifetime.

**Detection logic:** No effective round, timeout, or resource bound.

**False positives:** Very long but bounded business workflows.

**Severity:** Medium/High.

**CWE:** CWE-400.

**MITRE:** T1499.

**Remediation:** Maximum round count, state TTL and resource quotas.

**Regression:** Round-limit test.

---

### MCP-MRTR-005 — Oversized `requestState` / input amplification
**Objective:** Detect memory/CPU amplification through continuation state and inputs.

**Preconditions:** MRTR endpoint.

**Discovery:** Identify configurable maximum sizes.

**Passive test:** Record documented and observed limits.

**Active-safe test:** Incrementally test sizes below operational thresholds.

**Deep-pentest test:** Stress in a dedicated environment.

**Evidence:** Response time, memory, rejection thresholds.

**Detection logic:** Unbounded or dangerously large state is accepted.

**False positives:** Controlled limits consistent with the deployment.

**Severity:** Medium/High.

**CWE:** CWE-400.

**MITRE:** T1499.

**Remediation:** Size limits and streaming where appropriate.

**Regression:** Size-boundary suite.

---

## 24.6 Tasks

### MCP-TASK-001 — Task IDOR / ownership bypass
**Objective:** Ensure task IDs are not sufficient to access another principal's task.

**Preconditions:** Tasks extension enabled.

**Discovery:** Identify task creation and task lookup operations.

**Passive test:** Determine identifier entropy and ownership metadata.

**Active-safe test:** A creates a benign task; B attempts `tasks/get`.

**Deep-pentest test:** B attempts result retrieval/update/cancel in a sandbox.

**Evidence:** Task ID, principal, status/result visibility.

**Detection logic:** Cross-principal task access succeeds.

**False positives:** Deliberately shared task queues with explicit ACLs.

**Severity:** High/Critical.

**CWE:** CWE-639.

**MITRE:** T1210.

**Remediation:** Authorize every task operation against task owner/tenant.

**Regression:** Task ownership matrix.

---

### MCP-TASK-002 — Task enumeration
**Objective:** Prevent predictable or observable task IDs from enabling discovery.

**Preconditions:** Task IDs exposed to clients.

**Discovery:** Collect multiple task IDs.

**Passive test:** Measure entropy/patterns.

**Active-safe test:** Sample adjacent/prefix variants against canary tasks.

**Deep-pentest test:** Attempt bounded enumeration against a synthetic namespace.

**Evidence:** ID structure and acceptance pattern.

**Detection logic:** Low-entropy IDs expose task existence or contents.

**False positives:** High-entropy UUIDs with strict authorization.

**Severity:** Medium, High if paired with IDOR.

**CWE:** CWE-330 / CWE-639.

**MITRE:** T1087.

**Remediation:** Unpredictable IDs plus authorization; do not rely on secrecy.

**Regression:** Identifier entropy test.

---

### MCP-TASK-003 — Task cancel/update race
**Objective:** Detect invalid transitions caused by concurrent task operations.

**Preconditions:** Mutable task state.

**Discovery:** Record legal task state machine.

**Passive test:** Map transition rules.

**Active-safe test:** Race benign `get/update/cancel` operations.

**Deep-pentest test:** Attempt execute/update/cancel interleavings in a lab.

**Evidence:** Transition timeline and final side effects.

**Detection logic:** Terminal tasks can be revived, executed, or modified unexpectedly.

**False positives:** Explicitly idempotent cancel/update semantics.

**Severity:** High.

**CWE:** CWE-362 / CWE-841.

**MITRE:** T1190.

**Remediation:** Atomic task state transitions.

**Regression:** Transition-state race harness.

---

### MCP-TASK-004 — Task result after authorization loss
**Objective:** Prevent privileged results from remaining accessible after role/session/policy revocation.

**Preconditions:** Long-running or deferred task and revocable privileges.

**Discovery:** Determine result retention policy.

**Passive test:** Record result ACL lifetime.

**Active-safe test:** Revoke a test principal before completion and request the result.

**Deep-pentest test:** Attempt result retrieval after tenant transfer or account disablement in a sandbox.

**Evidence:** Authorization state versus result access.

**Detection logic:** Result remains available despite policy requiring reauthorization.

**False positives:** Explicit immutable-ownership business rules.

**Severity:** High/Critical.

**CWE:** CWE-862.

**MITRE:** T1078.

**Remediation:** Reauthorize protected results or securely transfer ownership.

**Regression:** Revocation-mid-task test.

---

## 24.7 Caching and isolation

### MCP-CACHE-001 — Cross-principal cache leakage
**Objective:** Ensure cached responses are not reused across incompatible authorization contexts.

**Preconditions:** Cache hints or observable server/proxy caching.

**Discovery:** Inspect `cacheScope`, `ttlMs`, cache headers, proxy behavior and response repetition.

**Passive test:** Compare cache keys/vary behavior.

**Active-safe test:** A requests a canary response; B requests the same operation and verifies content/metadata.

**Deep-pentest test:** Vary scopes/tenants and test cache hits under concurrent access.

**Evidence:** Request identity, response content/hash, cache indicators.

**Detection logic:** B receives A-scoped content or metadata.

**False positives:** Public response with no authorization-dependent content.

**Severity:** High/Critical.

**CWE:** CWE-525 / CWE-200.

**MITRE:** T1530 when data is exposed.

**Remediation:** Include security context in cache key or prohibit shared caching.

**Regression:** A/B cache-isolation run.

---

### MCP-CACHE-002 — Cache poisoning across authorization state
**Objective:** Detect a privileged/private response being stored under a publicly reusable cache key.

**Preconditions:** Cacheable endpoint.

**Discovery:** Identify cache scope and response headers.

**Passive test:** Review public/private cache classification.

**Active-safe test:** Prime cache with test principal A, then access using B and anonymous client.

**Deep-pentest test:** Prime different scopes and inspect downstream behavior in a lab.

**Evidence:** Cache hit/miss and differing response hashes.

**Detection logic:** A private response becomes available to B or anonymous requester.

**False positives:** Deliberately public data.

**Severity:** Critical.

**CWE:** CWE-525.

**MITRE:** T1530.

**Remediation:** Never mark authorization-dependent responses public; use `Vary`/private caching appropriately.

**Regression:** Cache-poison negative test.

---

### MCP-CACHE-003 — Stale-privilege reuse
**Objective:** Detect cached tool/resource/prompt data remaining available after permissions are revoked or changed.

**Preconditions:** Mutable access policy plus caching.

**Discovery:** Identify TTL and invalidation events.

**Passive test:** Review cache invalidation architecture.

**Active-safe test:** Prime a protected canary, revoke permission, request again.

**Deep-pentest test:** Repeat across instances and after token rotation.

**Evidence:** Pre/post-policy response comparison.

**Detection logic:** Sensitive cached content remains accessible beyond policy lifetime.

**False positives:** Explicitly versioned public artifacts.

**Severity:** High.

**CWE:** CWE-613 / CWE-525.

**MITRE:** T1078.

**Remediation:** Security-sensitive cache invalidation on authorization changes.

**Regression:** Permission-revocation cache test.

---

### MCP-CACHE-004 — Pagination cursor cross-user reuse
**Objective:** Ensure pagination cursors are scoped to principal, query, and dataset.

**Preconditions:** Paginated list endpoint.

**Discovery:** Capture next-page cursors.

**Passive test:** Determine cursor format/lifetime.

**Active-safe test:** A obtains cursor; B uses it.

**Deep-pentest test:** Alter query or page size while reusing the cursor.

**Evidence:** Cursor, principal, query and returned items.

**Detection logic:** Cursor grants access to another principal's dataset or bypasses filters.

**False positives:** Cursor represents a public immutable dataset.

**Severity:** High.

**CWE:** CWE-639.

**MITRE:** T1530.

**Remediation:** Bind cursor to principal and canonical query context.

**Regression:** Cursor ownership test.

---

## 24.8 Tool metadata and semantic/agent security

### MCP-AI-001 — Tool-description poisoning
**Objective:** Identify tool descriptions containing instructions that attempt to override security policy or manipulate agent behavior.

**Preconditions:** `tools/list` or equivalent tool metadata.

**Discovery:** Retrieve all tool metadata and normalize text.

**Passive test:** Detect system-role impersonation, secret requests, tool redirection, policy bypass language, hidden Unicode and suspicious URLs.

**Active-safe test:** Ask the test agent to describe which instructions it treats as authoritative without executing the requested side effect.

**Deep-pentest test:** Run a dedicated adversarial agent harness against a sandbox.

**Evidence:** Original metadata, normalized text, model decision trace if available.

**Detection logic:** Untrusted tool metadata can influence the agent into unsafe behavior or override higher-priority instructions.

**False positives:** Legitimate operational documentation.

**Severity:** Medium/High; Critical when paired with privileged tools.

**CWE:** CWE-74 / AI-specific taxonomy.

**MITRE:** T1059/T1204 as downstream behavior warrants.

**Remediation:** Treat tool metadata as untrusted data; isolate policy from descriptions.

**Regression:** Semantic poisoning corpus.

---

### MCP-AI-002 — Resource/result indirect prompt injection
**Objective:** Detect untrusted text in resources and tool results that can cause the agent to perform an unauthorized next action.

**Preconditions:** Agent executes MCP results, resources or prompts.

**Discovery:** Identify text-bearing outputs and downstream tools.

**Passive test:** Search for instruction-like content and trust-boundary crossings.

**Active-safe test:** Use a synthetic result containing an unmistakable canary instruction and observe whether the agent treats it as data or authority.

**Deep-pentest test:** Chain canary result → privileged read → synthetic egress in an isolated environment.

**Evidence:** Source text, agent decision, selected tool sequence.

**Detection logic:** Untrusted content changes execution outside the intended task policy.

**False positives:** Agent intentionally designed to execute instructions contained in trusted resources.

**Severity:** High/Critical when privileged actions follow.

**CWE:** CWE-74.

**MITRE:** T1059 / T1204.

**Remediation:** Provenance labels, policy gates, tool confirmation and least privilege.

**Regression:** Indirect-injection chain corpus.

---

### MCP-AI-003 — Split-instruction cross-channel attack
**Objective:** Detect attacks whose malicious intent is distributed across descriptions, resources, results, prompts, errors or another MCP server.

**Preconditions:** Multiple MCP content sources.

**Discovery:** Build a content-source graph.

**Passive test:** Search each source for fragments and correlate semantic completion.

**Active-safe test:** Use benign canary fragments that become meaningful only when combined.

**Deep-pentest test:** Demonstrate a complete cross-channel action chain in a sandbox.

**Evidence:** Fragment locations and resulting agent action.

**Detection logic:** Multiple individually benign inputs combine to override intended policy.

**False positives:** Normal task documentation spread across resources.

**Severity:** High/Critical.

**CWE:** CWE-74.

**MITRE:** T1059.

**Remediation:** Treat content provenance independently; apply policy outside model-generated instructions.

**Regression:** Multi-source semantic corpus.

---

### MCP-AI-004 — Server-instructions trust-boundary abuse
**Objective:** Detect server instructions that are implicitly elevated into model/system context.

**Preconditions:** `server/discover` or equivalent server instructions are consumed by the host.

**Discovery:** Retrieve instruction fields and host handling.

**Passive test:** Inspect whether instructions are injected into higher-priority context.

**Active-safe test:** Add a harmless canary instruction that conflicts with a host policy and observe precedence without executing tools.

**Deep-pentest test:** Demonstrate policy bypass in a sandboxed agent.

**Evidence:** Instruction text, host prompt/context placement, agent behavior.

**Detection logic:** Untrusted server text gains higher authority than intended.

**False positives:** Explicitly trusted server with documented system-level instructions.

**Severity:** High.

**CWE:** CWE-74.

**MITRE:** T1059.

**Remediation:** Keep server instructions in an explicitly untrusted context unless server trust is verified.

**Regression:** Instruction-precedence test.

---

### MCP-AI-005 — Tool shadowing / name collision
**Objective:** Detect duplicate or misleading tool names that cause the agent to select an attacker-controlled capability.

**Preconditions:** Multiple tools or multiple MCP servers.

**Discovery:** Normalize names, aliases, descriptions and server identity.

**Passive test:** Detect duplicate/similar/confusable names.

**Active-safe test:** Present safe shadow tools with unique canary behavior and verify explicit server identity is retained.

**Deep-pentest test:** Simulate a malicious server shadowing a trusted tool in a test host.

**Evidence:** Tool ranking/selection and provenance.

**Detection logic:** Agent or host selects a lower-trust tool when a higher-trust one was intended.

**False positives:** Intentional aliases with explicit qualification.

**Severity:** High.

**CWE:** CWE-345 / CWE-1021.

**MITRE:** T1036.

**Remediation:** Namespace tools by trusted server identity; show provenance to the model/user.

**Regression:** Shadowing collision suite.

---

### MCP-AI-006 — Rug-pull / tool-definition drift
**Objective:** Detect a trusted server changing tool behavior after initial approval or inventory.

**Preconditions:** Historical MCP inventory or repeated scans.

**Discovery:** Fingerprint names, descriptions, schemas, annotations, endpoints, scopes and publisher metadata.

**Passive test:** Compare current snapshot with prior trusted baseline.

**Active-safe test:** Re-query the same tool and compare canonicalized definitions.

**Deep-pentest test:** Simulate a version change and verify policy re-approval triggers.

**Evidence:** Before/after hashes and semantic diff.

**Detection logic:** Security-relevant definition changes occur without expected reauthorization.

**False positives:** Routine documentation/version updates with unchanged privilege.

**Severity:** Medium/High; Critical for dangerous capability expansion.

**CWE:** CWE-494 / supply-chain trust.

**MITRE:** T1195.

**Remediation:** Version/publisher pinning, semantic diffing, reapproval for privilege expansion.

**Regression:** Drift policy test.

---

### MCP-AI-007 — Annotation/metadata deception
**Objective:** Detect misleading safety annotations, read/write hints, destructive-operation labels, or output semantics.

**Preconditions:** Tools use annotations/metadata.

**Discovery:** Capture annotations and infer actual behavior from source/fingerprints where available.

**Passive test:** Compare annotation claims with capability sinks.

**Active-safe test:** Run non-destructive canary and compare declared versus observed behavior.

**Deep-pentest test:** Validate a mislabeled destructive operation in a sandbox.

**Evidence:** Annotation and sink classification.

**Detection logic:** Security policy relies on misleading metadata.

**False positives:** Informational metadata not used in authorization.

**Severity:** Medium/High.

**CWE:** CWE-345.

**MITRE:** T1036.

**Remediation:** Do not use self-attested annotations as authorization.

**Regression:** Metadata-vs-sink consistency test.

---

## 24.9 Tool sink security

### MCP-SINK-001 — Command/argument injection
**Objective:** Determine whether tool-controlled values can alter command interpretation or argument boundaries.

**Preconditions:** Tool invokes OS commands/CLIs.

**Discovery:** Static source analysis, executable/argument schema inference, runtime fingerprints.

**Passive test:** Identify shell APIs, command builders, `spawn`/`exec` patterns and user-controlled parameters.

**Active-safe test:** Use a benign separator/canary against a dedicated command wrapper that records argv without executing it.

**Deep-pentest test:** Validate shell/argv injection only in a disposable sandbox.

**Evidence:** Final argv, shell invocation mode, wrapper output.

**Detection logic:** Input changes executable, argument count, option interpretation, or shell syntax unexpectedly.

**False positives:** Proper `execve`-style argv handling with strict schema.

**Severity:** Critical if code execution is possible.

**CWE:** CWE-78 / CWE-88.

**MITRE:** T1059.

**Remediation:** Avoid shells; use fixed executable + structured argv + allowlists.

**Regression:** Argument-boundary corpus.

---

### MCP-SINK-002 — Leading-dash option injection
**Objective:** Detect values beginning with `-` or `--` being interpreted as CLI flags.

**Preconditions:** Tool passes user-controlled arguments to command-line programs.

**Discovery:** Infer command sink and argument positions.

**Passive test:** Review command APIs and whether `--` is used to terminate options.

**Active-safe test:** Submit a harmless leading-dash canary to a wrapper that logs argv.

**Deep-pentest test:** Validate privilege-changing or file-output options in a sandbox.

**Evidence:** Final argv and parser interpretation.

**Detection logic:** User input becomes an unintended CLI option.

**False positives:** Tool explicitly allows option passthrough as a documented feature.

**Severity:** High/Critical.

**CWE:** CWE-88.

**MITRE:** T1059.

**Remediation:** Reject leading-dash data where not required; insert `--`; use typed APIs.

**Regression:** Option-injection corpus.

---

### MCP-SINK-003 — Path traversal and filesystem escape
**Objective:** Detect file/resource parameters escaping intended directories.

**Preconditions:** Filesystem access or path-like parameters.

**Discovery:** Identify `file://`, path schemas, file tools and working directories.

**Passive test:** Canonicalize candidate paths and identify traversal/symlink risk.

**Active-safe test:** Use canary files in a disposable directory and test `../`, absolute, encoded and mixed-separator variants.

**Deep-pentest test:** Validate access to a dedicated sensitive canary outside the intended root.

**Evidence:** Resolved canonical path and file content hash.

**Detection logic:** Access escapes allowlisted root or follows attacker-controlled symlink.

**False positives:** Intentional unrestricted file tool.

**Severity:** High/Critical.

**CWE:** CWE-22 / CWE-59.

**MITRE:** T1083.

**Remediation:** Canonicalize, enforce root containment after resolution, and control symlinks.

**Regression:** Filesystem traversal corpus.

---

### MCP-SINK-004 — SQL/query injection
**Objective:** Detect MCP tool parameters reaching SQL, search, filter, or query languages without safe parameterization.

**Preconditions:** Database/query tool.

**Discovery:** Identify SQL/DSL APIs, query templates and free-form query parameters.

**Passive test:** Source/static query construction review.

**Active-safe test:** Use syntax canaries that should remain data, not executable query fragments.

**Deep-pentest test:** Confirm impact only against a disposable database.

**Evidence:** Prepared statement use, query logs, controlled response differences.

**Detection logic:** Input changes query structure unexpectedly.

**False positives:** Parameterized queries and typed query builders.

**Severity:** High/Critical.

**CWE:** CWE-89.

**MITRE:** T1190.

**Remediation:** Parameterized queries and strict query allowlists.

**Regression:** Injection corpus per query language.

---

### MCP-SINK-005 — Template / expression injection
**Objective:** Detect tool inputs reaching template engines or expression evaluators.

**Preconditions:** Template/report/automation tool.

**Discovery:** Identify template engines, expression evaluators and dynamic rendering.

**Passive test:** Search for string interpolation into template/eval APIs.

**Active-safe test:** Use inert expressions to determine whether evaluation occurs.

**Deep-pentest test:** Confirm code execution in a sandbox only.

**Evidence:** Evaluation behavior, engine fingerprint and controlled output.

**Detection logic:** Untrusted data becomes executable template/expression syntax.

**False positives:** Escaped templates or data-only engines.

**Severity:** High/Critical.

**CWE:** CWE-94 / CWE-1336.

**MITRE:** T1059.

**Remediation:** Data-only templating, strict sandboxing and escaping.

**Regression:** Engine-specific injection corpus.

---

## 24.10 SSRF and network-target validation

### MCP-SSRF-001 — Basic SSRF / internal target reachability
**Objective:** Detect network parameters that can reach unintended internal services.

**Preconditions:** Tool/resource accepts URL, host or network target.

**Discovery:** Identify URL/host/port parameters and network sinks.

**Passive test:** Normalize target parsers and configured egress rules.

**Active-safe test:** Use an operator-controlled callback domain and non-sensitive canary endpoints.

**Deep-pentest test:** Validate access to a disposable internal test service representing a private address range.

**Evidence:** Callback/request logs and resolved address.

**Detection logic:** User-controlled input reaches an unauthorized network location.

**False positives:** Deliberately open proxy/fetcher with explicit network policy.

**Severity:** High/Critical.

**CWE:** CWE-918.

**MITRE:** T1190 / T1046.

**Remediation:** Egress allowlist, DNS/IP validation and redirect controls.

**Regression:** SSRF canary suite.

---

### MCP-SSRF-002 — Private-address normalization bypass
**Objective:** Detect filters bypassed via alternate IPv4/IPv6 representations.

**Preconditions:** SSRF filter or private-network denylist.

**Discovery:** Determine parser and DNS library behavior.

**Passive test:** Generate canonical forms for loopback, RFC1918, link-local and mapped IPv6.

**Active-safe test:** Test non-routable canary addresses with no production side effects.

**Deep-pentest test:** Validate only against an isolated internal target.

**Evidence:** Original target, normalized address, decision.

**Detection logic:** One representation is blocked while an equivalent address is allowed.

**False positives:** Allowlisted internal fetcher.

**Severity:** High/Critical.

**CWE:** CWE-918.

**MITRE:** T1046.

**Remediation:** Resolve and compare canonical addresses at the final connect step.

**Regression:** IPv4/IPv6/NAT64/6to4/decimal/hex corpus.

---

### MCP-SSRF-003 — Redirect-based SSRF
**Objective:** Detect public URL validation followed by redirect into a blocked network.

**Preconditions:** HTTP client follows redirects.

**Discovery:** Determine redirect policy.

**Passive test:** Review maximum hops and destination revalidation.

**Active-safe test:** Use an operator-controlled redirector from public canary to another public canary.

**Deep-pentest test:** Redirect to an isolated private canary service.

**Evidence:** Complete redirect chain and final resolved address.

**Detection logic:** Only initial URL is validated.

**False positives:** Redirects disabled or revalidated correctly.

**Severity:** High.

**CWE:** CWE-918.

**MITRE:** T1190.

**Remediation:** Revalidate every redirect destination.

**Regression:** Redirect-chain SSRF suite.

---

### MCP-SSRF-004 — DNS rebinding / validation-to-connect race
**Objective:** Detect hostname validation that occurs separately from final network resolution.

**Preconditions:** Hostname-based SSRF control.

**Discovery:** Identify DNS resolution timing and HTTP client behavior.

**Passive test:** Review whether validation and connection share the same resolved address.

**Active-safe test:** Use a controlled hostname with rotating public addresses.

**Deep-pentest test:** Demonstrate a public→private resolution transition in a lab.

**Evidence:** DNS answers over time and connection destination.

**Detection logic:** Validation accepts one address, but connection occurs to a different restricted address.

**False positives:** Resolver pins IP and reuses same connection securely.

**Severity:** Critical.

**CWE:** CWE-367 / CWE-918.

**MITRE:** T1046.

**Remediation:** Resolve once, validate canonical IP, then connect to that exact validated address or use robust egress controls.

**Regression:** Rebinding harness.

---

## 24.11 OAuth and authorization-server discovery

### MCP-OAUTH-001 — Protected-resource metadata SSRF
**Objective:** Ensure fetching OAuth protected-resource metadata cannot be abused as an SSRF primitive.

**Preconditions:** Server performs discovery from a user-controlled or remotely specified origin.

**Discovery:** Identify discovery URL construction and fetch behavior.

**Passive test:** Map fetched URLs, redirect handling and proxy configuration.

**Active-safe test:** Point a test endpoint at a controlled callback.

**Deep-pentest test:** Redirect discovery to an isolated private canary service.

**Evidence:** Fetch log and resolved destination.

**Detection logic:** Discovery fetch reaches an unauthorized internal address.

**False positives:** Operator-configured trusted metadata endpoints.

**Severity:** High/Critical.

**CWE:** CWE-918.

**MITRE:** T1190.

**Remediation:** Strict allowlists and destination revalidation.

**Regression:** Discovery SSRF suite.

---

### MCP-OAUTH-002 — Authorization-server issuer mix-up
**Objective:** Prevent accepting tokens/metadata from an unexpected authorization server.

**Preconditions:** OAuth discovery and multiple potential issuers.

**Discovery:** Record issuer and authorization-server relationships.

**Passive test:** Compare configured issuer to discovered issuer.

**Active-safe test:** Present metadata from an unauthorized test issuer.

**Deep-pentest test:** Attempt complete authentication with the wrong issuer in a sandbox.

**Evidence:** Issuer metadata and token validation outcome.

**Detection logic:** Discovery trust is sufficient to establish issuer trust without explicit validation.

**False positives:** Explicit federation policy.

**Severity:** Critical.

**CWE:** CWE-287 / CWE-346.

**MITRE:** T1078.

**Remediation:** Bind accepted issuer(s) to explicit configuration/trusted metadata.

**Regression:** Wrong-issuer test.

---

### MCP-OAUTH-003 — Resource/client binding failure
**Objective:** Detect OAuth tokens or authorization grants being accepted outside their intended MCP protected resource/client.

**Preconditions:** OAuth authorization flow.

**Discovery:** Inspect `resource`, audience, client ID, redirect URI and PKCE relationships.

**Passive test:** Build the expected binding matrix.

**Active-safe test:** Use test credentials with mismatched resource/client parameters.

**Deep-pentest test:** Attempt token reuse across sibling MCP endpoints in a lab.

**Evidence:** Authorization request, token claims, resource, client identity.

**Detection logic:** Mismatched binding still produces authorization.

**False positives:** Deliberately shared multi-resource trust.

**Severity:** High/Critical.

**CWE:** CWE-346.

**MITRE:** T1078.

**Remediation:** Validate all relevant resource/client binding parameters.

**Regression:** Cross-resource token matrix.

---

### MCP-OAUTH-004 — PKCE/state/redirect validation failure
**Objective:** Detect OAuth flow weaknesses that allow code interception or login CSRF.

**Preconditions:** Authorization-code flow.

**Discovery:** Identify state, nonce, PKCE and redirect URI handling.

**Passive test:** Inspect whether these values are generated, stored and verified.

**Active-safe test:** Use test authorization codes and deliberately mismatched state/verifier/redirect URI.

**Deep-pentest test:** Validate a complete authorization-code substitution chain in a sandbox.

**Evidence:** Authorization request and rejection/acceptance.

**Detection logic:** Missing or mismatched protections are accepted.

**False positives:** Flow not using authorization code because another explicit grant is used.

**Severity:** High.

**CWE:** CWE-352 / CWE-287.

**MITRE:** T1187.

**Remediation:** Enforce state, PKCE, exact redirect URI and nonce semantics as applicable.

**Regression:** OAuth negative matrix.

---

## 24.12 Resources, templates, prompts, and data access

### MCP-DATA-001 — Sensitive resource exposure
**Objective:** Detect resources exposing secrets, system files, credentials, private repositories, or internal configuration.

**Preconditions:** `resources/list` or templates, or equivalent data capability.

**Discovery:** Enumerate URI schemes, paths, MIME types, descriptions and content classes.

**Passive test:** Classify sensitivity and exposure scope.

**Active-safe test:** Read only synthetic canary resources and metadata.

**Deep-pentest test:** Validate access to a designated sensitive canary outside the expected trust zone.

**Evidence:** URI, authorization, sensitivity classifier and response hash.

**Detection logic:** Sensitive content is exposed to an unauthorized principal or overly broad tool.

**False positives:** Deliberately public documentation.

**Severity:** High/Critical.

**CWE:** CWE-200.

**MITRE:** T1552 / T1530.

**Remediation:** Minimize resources, scope access and redact secrets.

**Regression:** Sensitive-resource inventory.

---

### MCP-DATA-002 — Resource-template traversal / parameter injection
**Objective:** Ensure user-controlled template variables cannot escape intended resource scope.

**Preconditions:** `resources/templates/list`.

**Discovery:** Extract URI templates and variable schemas.

**Passive test:** Identify path/URL variables.

**Active-safe test:** Use traversal and alternate-authority canaries.

**Deep-pentest test:** Resolve only against designated canary resources.

**Evidence:** Expanded URI and final resource.

**Detection logic:** Variable changes authority/path/security boundary.

**False positives:** Templates intentionally support arbitrary resources with explicit ACLs.

**Severity:** High.

**CWE:** CWE-22 / CWE-918.

**MITRE:** T1190.

**Remediation:** Validate each expanded component after canonicalization.

**Regression:** Template fuzz corpus.

---

### MCP-DATA-003 — Prompt metadata abuse
**Objective:** Detect malicious prompt names/descriptions/arguments that cause policy confusion or data exfiltration.

**Preconditions:** Prompt inventory.

**Discovery:** Enumerate prompts and argument schemas.

**Passive test:** Search prompt metadata for policy override and secret-handling patterns.

**Active-safe test:** Invoke only benign prompts against a test agent and inspect resulting tool selection without execution.

**Deep-pentest test:** Run prompt-chain tests in a sandbox.

**Evidence:** Prompt metadata and resulting agent plan.

**Detection logic:** Prompt metadata can bypass the host's intended instruction hierarchy.

**False positives:** Legitimate operational prompt templates.

**Severity:** Medium/High.

**CWE:** CWE-74.

**MITRE:** T1059.

**Remediation:** Keep prompt content separate from security policy and require explicit tool authorization.

**Regression:** Prompt-poisoning suite.

---

## 24.13 Cross-server and capability-chain security

### MCP-CHAIN-001 — Read → egress/execution capability chain
**Objective:** Identify whether a single server can read sensitive data and independently exfiltrate or execute with that data.

**Preconditions:** Tool/resource graph contains read plus outbound/execution capability.

**Discovery:** Classify tools into `read`, `transform`, `egress`, `execute`, `identity` capabilities.

**Passive test:** Construct a directed capability graph.

**Active-safe test:** Use synthetic canary data and a controlled external sink.

**Deep-pentest test:** Complete a controlled end-to-end exfiltration/execution chain in a lab.

**Evidence:** Capability path and canary receipt.

**Detection logic:** Untrusted input can flow from sensitive read to external sink/execution without an explicit policy gate.

**False positives:** Purpose-built data transfer tools with explicit consent and network policy.

**Severity:** High/Critical.

**CWE:** CWE-200 / CWE-94 / CWE-918.

**MITRE:** T1041 / T1059.

**Remediation:** Separate read and egress authority; require explicit policy gates.

**Regression:** Capability graph recomputation after every inventory change.

---

### MCP-CHAIN-002 — Cross-server capability chaining
**Objective:** Detect harmful capability combinations that do not exist inside any single MCP server.

**Preconditions:** Multiple MCP servers available to the same host/agent.

**Discovery:** Build graph across all server tools/resources.

**Passive test:** Find paths such as `private-read → transform → egress`, `browser → credential → cloud`, `git → shell`.

**Active-safe test:** Use canary data and non-destructive synthetic egress.

**Deep-pentest test:** Complete a selected chain in a sandbox.

**Evidence:** Server-by-server sequence and data flow.

**Detection logic:** Combination of individually legitimate capabilities permits an unsafe end-to-end action.

**False positives:** Explicitly authorized workflows with user confirmation.

**Severity:** High/Critical.

**CWE:** CWE-441 / CWE-200.

**MITRE:** T1041 / T1190.

**Remediation:** Apply host-level capability policy across servers, not per-server alone.

**Regression:** Whole-host attack graph.

---

### MCP-CHAIN-003 — Confused deputy through privileged MCP server
**Objective:** Detect a lower-trust requester causing a more privileged MCP server to perform an action on its behalf.

**Preconditions:** Server exposes credentials or authority broader than caller's authority.

**Discovery:** Map token/service-account identity used for downstream calls.

**Passive test:** Compare caller identity versus downstream identity.

**Active-safe test:** Use a harmless downstream canary operation under two caller identities.

**Deep-pentest test:** Attempt a privileged action beyond caller's entitlement in a sandbox.

**Evidence:** Caller identity, downstream identity, requested action and result.

**Detection logic:** Server acts with authority not justified by caller context.

**False positives:** Deliberate broker with correct policy enforcement.

**Severity:** Critical.

**CWE:** CWE-441.

**MITRE:** T1134.

**Remediation:** Downstream authorization must consider caller identity and intended delegation.

**Regression:** Delegation matrix.

---

## 24.14 MCP Apps and UI-mediated execution

### MCP-APP-001 — `postMessage` origin/source validation
**Objective:** Ensure host/UI communication accepts messages only from the expected source and origin.

**Preconditions:** MCP Apps UI extension.

**Discovery:** Identify iframe, `postMessage` and message handlers.

**Passive test:** Review allowed origins and source checks.

**Active-safe test:** Send benign message types from an unexpected origin/source in a test harness.

**Deep-pentest test:** Attempt privileged UI action through forged message in a sandbox.

**Evidence:** Message, origin, source, handler outcome.

**Detection logic:** Untrusted window can invoke privileged host behavior.

**False positives:** Explicitly permissive messaging within a trusted sandbox boundary.

**Severity:** High/Critical.

**CWE:** CWE-346 / CWE-345.

**MITRE:** T1189.

**Remediation:** Check both `origin` and `source`; validate message schema and capability.

**Regression:** Cross-origin messaging test.

---

### MCP-APP-002 — CSP / external resource trust
**Objective:** Detect UI content that can load unapproved scripts, frames, network destinations, or other external content.

**Preconditions:** MCP Apps application with CSP metadata.

**Discovery:** Parse CSP, iframe sandbox flags and referenced domains.

**Passive test:** Enumerate script/connect/frame/img/font origins.

**Active-safe test:** Load in a harness with controlled sink domains.

**Deep-pentest test:** Attempt forbidden script or network load in a sandbox.

**Evidence:** CSP and observed network requests.

**Detection logic:** UI can reach or execute outside approved capability boundaries.

**False positives:** Explicitly allowed CDN/network origins.

**Severity:** Medium/High.

**CWE:** CWE-693 / CWE-79.

**MITRE:** T1189.

**Remediation:** Tight CSP and least-privilege sandboxing.

**Regression:** CSP diff/test.

---

### MCP-APP-003 — UI capability escalation / approval mismatch
**Objective:** Ensure a UI action cannot silently invoke a more privileged tool than the user intended to approve.

**Preconditions:** MCP Apps can trigger tool calls.

**Discovery:** Map UI controls to host tool requests.

**Passive test:** Compare displayed labels, tool names and required scopes.

**Active-safe test:** Use a test UI with a benign alternate action and verify the exact call/parameters shown to the host.

**Deep-pentest test:** Simulate UI content replacement after approval in a sandbox.

**Evidence:** UI label, tool name, parameters and user approval event.

**Detection logic:** Approved action differs materially from executed action.

**False positives:** UI labels that intentionally represent a workflow with an explicit second confirmation.

**Severity:** High/Critical.

**CWE:** CWE-451 / CWE-862.

**MITRE:** T1056.

**Remediation:** Bind approval to exact tool/parameters and re-authorize changed requests.

**Regression:** UI-to-tool binding test.

---

## 24.15 Local/stdio MCP security

### MCP-LOCAL-001 — MCP configuration command injection
**Objective:** Detect untrusted configuration fields that become executable local commands.

**Preconditions:** stdio/local MCP configuration or project files.

**Discovery:** Scan config files, manifests, notebook metadata and launchers.

**Passive test:** Identify executable command, arguments, environment and working-directory sources.

**Active-safe test:** Resolve command without executing it and compare against allowlist.

**Deep-pentest test:** Execute only within an isolated test runner.

**Evidence:** Config source, resolved executable and argv.

**Detection logic:** Untrusted data controls local process execution without sufficient trust boundary.

**False positives:** Explicitly trusted local developer configuration.

**Severity:** Critical.

**CWE:** CWE-78 / CWE-94.

**MITRE:** T1059.

**Remediation:** Signed/approved configurations, absolute executable paths and strict provenance.

**Regression:** Config provenance test.

---

### MCP-LOCAL-002 — PATH hijacking / executable resolution
**Objective:** Detect local MCP processes resolving a different executable because of mutable `PATH` or working directory.

**Preconditions:** stdio launcher uses relative executable/path resolution.

**Discovery:** Inspect command path and environment inheritance.

**Passive test:** Resolve actual executable under current and sanitized environments.

**Active-safe test:** Use a harmless duplicate-name canary in a disposable directory to confirm resolution behavior.

**Deep-pentest test:** Demonstrate takeover only in an isolated sandbox.

**Evidence:** Resolved executable path and environment.

**Detection logic:** Attacker-controlled location can win executable resolution.

**False positives:** Controlled developer environment where integrity is guaranteed.

**Severity:** High/Critical.

**CWE:** CWE-426 / CWE-427.

**MITRE:** T1574.

**Remediation:** Use absolute paths and sanitized environment.

**Regression:** Executable-resolution test.

---

### MCP-LOCAL-003 — Environment/credential inheritance
**Objective:** Detect MCP processes inheriting credentials or sensitive environment variables unnecessarily.

**Preconditions:** stdio process launch.

**Discovery:** Enumerate inherited environment variables and credential providers.

**Passive test:** Compare required versus inherited secrets.

**Active-safe test:** Launch a canary server and record only variable names/classifications, not secret values.

**Deep-pentest test:** Confirm whether a canary credential is accessible to an untrusted server process.

**Evidence:** Variable classification and process identity.

**Detection logic:** Untrusted MCP server inherits secrets broader than required.

**False positives:** Required service credential with isolated trusted code.

**Severity:** High/Critical.

**CWE:** CWE-522 / CWE-200.

**MITRE:** T1552.001.

**Remediation:** Explicit environment allowlist and secret broker/token exchange.

**Regression:** Environment inheritance snapshot.

---

### MCP-LOCAL-004 — stdio protocol contamination
**Objective:** Ensure server stdout/stderr behavior cannot corrupt protocol parsing or leak sensitive data.

**Preconditions:** stdio MCP server.

**Discovery:** Inspect process output handling.

**Passive test:** Capture startup/runtime output channels.

**Active-safe test:** Trigger benign errors and observe whether protocol messages are contaminated.

**Deep-pentest test:** Inject large/noisy output from a test server.

**Evidence:** Raw stdout/stderr and client interpretation.

**Detection logic:** Logs on protocol channel alter parsing or expose secrets to the host.

**False positives:** Properly separated stderr logging.

**Severity:** Medium/High.

**CWE:** CWE-116 / CWE-200.

**MITRE:** T1071.

**Remediation:** Reserve protocol stdout; sanitize logs and bound buffers.

**Regression:** Noisy-stdio parser test.

---

## 24.16 Denial of service and resource exhaustion

### MCP-DOS-001 — Request/body/schema amplification
**Objective:** Detect unbounded JSON, schema, array, string or nesting resource consumption.

**Preconditions:** JSON-RPC/MCP endpoint.

**Discovery:** Observe documented and effective size limits.

**Passive test:** Review parser/body limits.

**Active-safe test:** Increment payload size within controlled boundaries.

**Deep-pentest test:** Load test in a dedicated environment.

**Evidence:** Thresholds, memory/CPU and response times.

**Detection logic:** Resource usage grows without effective bounds.

**False positives:** Large but bounded enterprise payload limits.

**Severity:** Medium/High/Critical depending on availability impact.

**CWE:** CWE-400.

**MITRE:** T1499.

**Remediation:** Hard limits, streaming parsers and quotas.

**Regression:** Boundary-size tests.

---

### MCP-DOS-002 — SSE/stream buffering exhaustion
**Objective:** Detect unbounded buffering of incomplete/large stream events.

**Preconditions:** SSE or streaming transport.

**Discovery:** Identify stream parser and buffer limits.

**Passive test:** Inspect configured maximum event/message sizes.

**Active-safe test:** Send slow or fragmented bounded test messages.

**Deep-pentest test:** Exhaust buffers only in a dedicated environment.

**Evidence:** Memory growth, connection count, timeout behavior.

**Detection logic:** Incomplete/large stream can consume disproportionate resources.

**False positives:** Correctly bounded parser with predictable rejection.

**Severity:** High.

**CWE:** CWE-400.

**MITRE:** T1499.

**Remediation:** Stream size/time limits and backpressure.

**Regression:** Slow/fragmented stream corpus.

---

### MCP-DOS-003 — Task/MRTR flooding
**Objective:** Prevent unlimited deferred tasks or continuation states from consuming storage and workers.

**Preconditions:** Tasks/MRTR support.

**Discovery:** Identify creation quotas and retention.

**Passive test:** Review rate limits and cleanup policy.

**Active-safe test:** Create a small bounded number of synthetic tasks/states.

**Deep-pentest test:** Load test in a disposable environment.

**Evidence:** Queue depth, storage growth, cleanup rate.

**Detection logic:** No meaningful per-principal quotas or TTLs.

**False positives:** External queue/storage quotas already enforce the boundary.

**Severity:** Medium/High.

**CWE:** CWE-400.

**MITRE:** T1499.

**Remediation:** Per-principal quotas, TTLs and backpressure.

**Regression:** Flood-control test.

---

## 24.17 Logging, tracing, and telemetry

### MCP-TELEM-001 — Sensitive data in logs
**Objective:** Detect tokens, API keys, tool arguments, resource contents, requestState and other secrets in logs.

**Preconditions:** Access to application/proxy/trace logs or a test environment.

**Discovery:** Inventory logging sinks.

**Passive test:** Search for secret patterns and sensitive field names.

**Active-safe test:** Send unique canary credentials and inspect logs, never real secrets.

**Deep-pentest test:** Confirm whether downstream observability systems retain sensitive content.

**Evidence:** Sanitized matching log records.

**Detection logic:** Sensitive credential or payload data is logged without approved controls.

**False positives:** Deliberately redacted or test-only values.

**Severity:** High/Critical for bearer tokens or credentials.

**CWE:** CWE-532.

**MITRE:** T1552.

**Remediation:** Structured redaction and field-level allowlists.

**Regression:** Canary-secret logging test.

---

### MCP-TELEM-002 — Trace-context spoofing / tenant confusion
**Objective:** Detect attacker-controlled trace metadata changing attribution or causing cross-request data correlation.

**Preconditions:** W3C trace context or similar telemetry.

**Discovery:** Identify accepted trace headers and propagation behavior.

**Passive test:** Determine whether trace IDs influence authorization/log identity.

**Active-safe test:** Supply arbitrary trace IDs/baggage.

**Deep-pentest test:** Attempt cross-tenant trace correlation or log injection in a lab.

**Evidence:** Trace/log output and security identity.

**Detection logic:** Trace metadata is trusted as an identity/security signal.

**False positives:** Trace IDs used only for diagnostics with no security impact.

**Severity:** Medium, High if attribution can be spoofed.

**CWE:** CWE-345 / CWE-117.

**MITRE:** T1562.

**Remediation:** Treat trace context as untrusted metadata.

**Regression:** Trace isolation test.

---

## 24.18 Supply chain, configuration, and publisher trust

### MCP-SUPPLY-001 — Dependency/version vulnerability correlation
**Objective:** Detect vulnerable MCP SDK/server/library versions and correlate them with reachable exposure.

**Preconditions:** Version fingerprints, SBOM, package lockfiles, container metadata, or source.

**Discovery:** Identify component name/version and dependency graph.

**Passive test:** Correlate with CVE/advisory feeds and fixed versions.

**Active-safe test:** Confirm runtime version without exploitation.

**Deep-pentest test:** Regression-test the vulnerable behavior in an isolated copy where required.

**Evidence:** Component fingerprint, advisory, fixed version, exposure path.

**Detection logic:** Vulnerable component is deployed on a reachable/high-impact attack path.

**False positives:** Backported vendor patches or mitigations.

**Severity:** Advisory severity adjusted by exploitability/exposure.

**CWE:** N/A, advisory-specific.

**MITRE:** T1195.

**Remediation:** Patch, backport, isolate or compensate.

**Regression:** Dependency inventory on every build.

---

### MCP-SUPPLY-002 — Publisher/server identity spoofing
**Objective:** Ensure self-reported server name/version/publisher metadata is not used as proof of identity.

**Preconditions:** MCP catalog/registry/host trusts server metadata.

**Discovery:** Compare metadata to actual endpoint, signed package, repository and configured trust identity.

**Passive test:** Detect self-reported identity fields.

**Active-safe test:** Replace metadata with a canary identity on a test endpoint and observe host trust behavior.

**Deep-pentest test:** Simulate a malicious server with a trusted-looking name in a sandbox.

**Evidence:** Metadata versus trusted provenance.

**Detection logic:** Trust is granted based on self-attested metadata.

**False positives:** Metadata used for display only.

**Severity:** High where authorization or installation depends on it.

**CWE:** CWE-345.

**MITRE:** T1036 / T1195.

**Remediation:** Use signed/provenance-backed identity and configured trust roots.

**Regression:** Identity spoof test.

---

### MCP-SUPPLY-003 — OCI/package/config metadata execution
**Objective:** Detect apparently passive metadata influencing runtime command execution or privileges.

**Preconditions:** MCP server packaged as container/image/package or launched from config metadata.

**Discovery:** Parse image labels, entrypoints, package scripts, manifests, notebook/project metadata and environment substitutions.

**Passive test:** Trace metadata fields into runtime argv/environment.

**Active-safe test:** Replace a field with a benign canary and inspect resolved launch configuration.

**Deep-pentest test:** Validate controlled runtime influence in a disposable runner.

**Evidence:** Source metadata → runtime command mapping.

**Detection logic:** Untrusted metadata can control executable, arguments, environment or privilege.

**False positives:** Signed immutable metadata from trusted build pipeline.

**Severity:** High/Critical.

**CWE:** CWE-78 / CWE-94 / CWE-494.

**MITRE:** T1195.002.

**Remediation:** Sign/validate metadata, pin versions, and separate data from executable configuration.

**Regression:** Metadata-to-runtime taint test.

---

## 24.19 Drift, catalog, and long-horizon monitoring

### MCP-DRIFT-001 — Capability drift
**Objective:** Detect changes in tool/resource/prompt/task capabilities over time.

**Preconditions:** At least two inventory snapshots.

**Discovery:** Canonicalize and fingerprint all primitives.

**Passive test:** Semantic diff names, descriptions, schemas, scopes, endpoints and annotations.

**Active-safe test:** Re-run discovery after deployment/version changes.

**Deep-pentest test:** Validate a simulated privilege expansion against approval policy.

**Evidence:** Before/after diff.

**Detection logic:** Capability expands without an approved change.

**False positives:** Planned releases not yet linked to change-management metadata.

**Severity:** Medium/High; Critical for privilege expansion.

**CWE:** CWE-494.

**MITRE:** T1195.

**Remediation:** Approval-gated capability changes.

**Regression:** Snapshot diff in CI/CD.

---

### MCP-DRIFT-002 — Endpoint/OAuth policy drift
**Objective:** Detect changes to server origin, TLS, redirect behavior, issuer, audience, scopes, or discovery metadata.

**Preconditions:** Historical configuration snapshot.

**Discovery:** Collect endpoint and auth metadata continuously.

**Passive test:** Compute policy diff.

**Active-safe test:** Validate current endpoint and issuer against baseline.

**Deep-pentest test:** Attempt access through an old/new policy mismatch in a lab.

**Evidence:** Before/after security metadata.

**Detection logic:** Security-relevant auth/transport policy changes outside approved baseline.

**False positives:** Planned endpoint migration with overlapping trust.

**Severity:** High.

**CWE:** CWE-346 / CWE-295.

**MITRE:** T1078.

**Remediation:** Version and approve security policy changes.

**Regression:** Auth-policy drift check.

---

## 24.20 MCP future zero-day research queue

These are **research hypotheses and likely bug classes**, not claims of existing zero-days unless separately correlated to a published advisory.

| Priority | Hypothesis | Why it is interesting | How to test |
|---|---|---|---|
| P0 | MRTR state confused deputy | New stateful continuation boundary | Cross-principal replay, target substitution, authorization revocation between rounds |
| P0 | Header/body desynchronization | Multiple parsers can authorize and execute differently | Proxy/gateway/backend differential harness |
| P0 | Stateless cross-instance credential leakage | Stateless deployments remove some session assumptions but introduce shared-state bugs | A/B concurrency across instances and shared pools |
| P0 | Cache authorization-context confusion | New cache semantics combine with multi-tenant auth | Prime under A, consume under B/anonymous, vary scope |
| P0 | Task + MRTR state confusion | Two state machines interact | Task pause/resume/update/cancel under interleaving identities |
| P0 | OAuth discovery SSRF variants | Discovery fetches are becoming security-critical | Redirect, rebinding, alternate IP forms, IPv6/NAT64, proxy rewrites |
| P1 | MCP Apps confused deputy | UI messaging can trigger privileged host actions | `postMessage` origin/source and approval-binding fuzzing |
| P1 | Cross-server capability chain | Dangerous authority emerges only after composition | Build global read→transform→egress/execute paths |
| P1 | Semantic tool shadowing | Names/metadata can affect agent tool choice | Confusable names, near-duplicates, server provenance changes |
| P1 | Rug-pull after approval | Tool definitions may change after trust is established | Continuous semantic diff + reauthorization policy |
| P1 | Security-control/sink mismatch | Validation exists but is bypassed downstream | Trace every security control to final sink |
| P1 | Parser canonicalization differential | SDK/proxy/JSON parser differences recur | Duplicate fields, Unicode, encoded paths, header variants |
| P2 | Long-horizon agent memory contamination | Future hosts may persist tool/resource-derived memory | Seed canaries and test later autonomous reuse |
| P2 | Extension interaction bugs | Each extension may be safe alone but unsafe in combination | Pairwise/three-way capability composition fuzzing |

---

# 25. MCP Scanner Architecture

The MCP module should run as a set of cooperating engines:

```text
                      MCP SECURITY ENGINE
                              |
      +-----------------------+-----------------------+
      |                       |                       |
 DISCOVERY              ACTIVE TESTING          STATIC / SOURCE
      |                       |                       |
 versions             auth matrix             sink detection
 capabilities          state tests             taint analysis
 extensions             cache tests             dependency scan
 identities             race tests              config scan
      |                       |                       |
      +-----------------------+-----------------------+
                              |
                       SECURITY GRAPH
                              |
              +---------------+----------------+
              |               |                |
           Identity         Dataflow       Capability
              |               |                |
       users/tokens       read/write        tools
       scopes             transform        resources
       tenants            egress           tasks
       publishers         execute          apps
              |               |                |
              +---------------+----------------+
                              |
                        AGENT SECURITY
                              |
          prompt injection / poisoning / shadowing
          server instructions / result injection
          cross-server chains / rug pulls
                              |
                           RISK
                              |
                  severity × exploitability
                  × exposure × impact
                  × confidence × control quality
```

## 25.1 Finding object

Each finding produced by the module should store:

```text
finding_id
asset_id
mcp_server_id
mcp_server_version
transport
protocol_version
extension
principal
source
sink
method
tool/resource/prompt/task
input_parameter
attack_class
test_id
severity
confidence
exploitability
blast_radius
cwe
mitre
cve_references
first_seen
last_seen
state
request_evidence
response_evidence
trace_evidence
before_after_snapshot
remediation
regression_test_id
```

## 25.2 Risk scoring

Use a compound score rather than raw CVSS alone:

```text
Risk =
    Technical Severity
  × Exposure
  × Privilege
  × Data Sensitivity
  × Exploitability
  × Blast Radius
  × Automation Potential
  × Confidence
```

A moderate prompt-injection finding on a public read-only MCP server should not automatically outrank a medium-severity authorization bug on a privileged cloud-management server.

---

# 26. MCP Regression Corpus

Maintain a permanent regression corpus grouped by:

```text
protocol parsing
HTTP/header differentials
JSON canonicalization
OAuth
identity and tenant isolation
MRTR
Tasks
cache
resources/templates
filesystem
SSRF
command/argument injection
SQL/query injection
MCP Apps
stdio
DoS
logging
supply chain
semantic injection
cross-server chaining
rug pull / drift
```

Each production finding must become a **minimal deterministic regression test** that runs without requiring the original exploit payload or destructive side effect.

---

# 27. MCP Integration With the Overall ASM

MCP should not be a special isolated scanner. It should connect to the broader ASM graph:

```text
Internet asset
   ↓
DNS / TLS / HTTP
   ↓
MCP endpoint
   ↓
MCP server identity
   ↓
OAuth / service identity
   ↓
tools / resources / prompts / tasks
   ↓
downstream API / cloud / DB / filesystem / browser
   ↓
data / execution
```

The ASM engine should therefore enrich an MCP finding with:

```text
asset exposure
cloud account / subscription / project
internet reachability
identity privilege
secret ownership
software/version/CVE
network path
third-party dependency
data sensitivity
other MCP servers
cross-server attack paths
```

This allows the platform to detect paths such as:

```text
Public MCP endpoint
   ↓
weak OAuth validation
   ↓
privileged service identity
   ↓
cloud API tool
   ↓
private object storage
   ↓
sensitive data
```

or:

```text
Untrusted resource content
   ↓
agent prompt injection
   ↓
filesystem read tool
   ↓
secret file
   ↓
HTTP egress tool
```

Those paths are the primary unit of risk, not isolated MCP method failures.

---

# 28. Operational Scan Profiles

### Profile: External ASM

```text
Discovery
Fingerprinting
Protocol validation
Unauthenticated exposure
OAuth metadata
Tool/resource/prompt inventory
Static metadata analysis
Passive CVE correlation
Safe SSRF callbacks
Drift baseline
```

### Profile: Authenticated Security Validation

```text
All External ASM controls
Role matrix
Cross-principal isolation
Hidden tool testing
Cache isolation
Task ownership
MRTR state tests
Resource authorization
Tool authorization
Logging validation
```

### Profile: Deep Red Team

```text
All previous controls
Multi-server chains
MRTR state-machine fuzzing
Task races
Concurrency fuzzing
Command/argument sinks
Filesystem traversal
SSRF variants
MCP Apps security
stdio/config execution
Sandboxed RCE validation
Long-horizon agent attacks
Supply-chain simulations
```

### Profile: Continuous Monitoring

```text
New MCP endpoint
New server/tool/resource/prompt/task
Capability drift
OAuth/issuer drift
TLS/transport drift
New exposed downstream identity
New CVE/advisory
New external destination
New dangerous capability chain
New tool poisoning signal
New publisher/package change
```

---

# 45. General Future Zero-Day Research Themes Outside MCP

The same reasoning applies to the broader attack surface.

## A. Parser differentials

Likely anywhere multiple layers parse the same request:

```text
CDN
WAF
reverse proxy
API gateway
application
framework
service
```

Test differences in:

```text
headers
encoding
Unicode
path normalization
HTTP method
JSON
multipart
chunking
compression
```

## B. Identity-context confusion

Look for:

```text
request authenticated as A
resource resolved as B
cached under C
executed as D
```

This is a broad future vulnerability family.

## C. Ephemeral infrastructure blind spots

Traditional scanners miss assets that exist only briefly:

```text
CI preview environment
feature branch deployment
temporary API
ephemeral container
short-lived cloud resource
serverless endpoint
temporary staging
AI evaluation environment
```

The platform must detect assets through event streams and historical observations, not just periodic scanning.

## D. Cloud IPv6/private-network bypasses

Every SSRF/private-network control should be tested through semantic address normalization.

## E. Supply-chain metadata execution

Do not only inspect source code. Inspect:

```text
image labels
package metadata
build metadata
CI parameters
configuration
registry manifests
release metadata
catalog entries
```

The Docker/MCP ecosystem already demonstrates why apparently passive metadata can influence runtime behavior.

## F. Agentic capability chaining

The future attack is increasingly:

```text
input
 → agent
 → tool A
 → result
 → tool B
 → identity
 → cloud
 → data
```

The attacker does not need one catastrophic bug if the system composes several legitimate capabilities unsafely.

---

# 46. Attack Graph Data Model

Use a graph, not a flat finding table.

## Node types

```text
organization
domain
subdomain
ip
cidr
asn
certificate
port
service
webapp
api
endpoint
cloud_account
cloud_resource
identity
role
oauth_app
repository
package
image
container
cluster
workload
secret
database
bucket
queue
saas_app
mobile_app
device
ai_model
ai_endpoint
agent
mcp_server
mcp_tool
mcp_resource
mcp_prompt
mcp_task
mcp_app
```

## Relationship types

```text
OWNS
RESOLVES_TO
PRESENTS_CERTIFICATE
HOSTS
RUNS
DEPENDS_ON
CALLS
AUTHENTICATES_TO
CAN_ACCESS
CAN_ASSUME
TRUSTS
EXPOSES
REDIRECTS_TO
CACHE_OF
DEPLOYS
BUILDS
PUBLISHES
USES
READS
WRITES
EXECUTES
EGRESSES_TO
INVOKES
CONTAINS
```

## Example attack path

```text
Internet
  |
  v
Public API
  |
  v
BOLA
  |
  v
Tenant object
  |
  v
Service identity
  |
  v
Cloud role
  |
  v
Private bucket
  |
  v
Sensitive document
```

Another:

```text
Public MCP Server
  |
  v
Tool poisoning
  |
  v
Agent
  |
  v
filesystem.read
  |
  v
private credential
  |
  v
http.post
  |
  v
external destination
```

---

# 47. Risk Scoring

Do not rank purely on CVSS.

Use a composite score:

```text
Risk =
Exposure
× Exploitability
× Privilege
× Data Sensitivity
× Reachability
× Attack-Path Confidence
× Persistence
× Blast Radius
```

Suggested qualitative factors:

| Factor | Low | High |
|---|---|---|
| Exposure | internal | public unauthenticated |
| Exploitability | complex/manual | trivial/automatable |
| Privilege | read-only | admin/root/cloud control |
| Data | public | credentials/crown jewels |
| Reachability | isolated | broad downstream graph |
| Confidence | inferred | directly validated |
| Persistence | transient | persistent access |
| Blast radius | single asset | organization-wide |

Also incorporate:

```text
CISA KEV
EPSS
asset criticality
business owner
customer-facing status
internet exposure duration
exploit availability
compensating controls
```

---

# 48. Finding Confidence Model

Every finding should have a confidence score.

```text
Observed
  > Fingerprinted
  > Correlated
  > Version-matched
  > Behaviorally validated
  > OOB-confirmed
  > Reproduced under authorization
```

Example:

```text
CVE inferred from banner              confidence: 0.42
Version confirmed from package         0.78
Version + vulnerable behavior          0.91
Behavior + safe exploit canary         0.97
```

This reduces false positives while preserving useful leads.

---

# 49. Continuous Monitoring Strategy

Different assets need different cadences.

| Asset | Suggested cadence |
|---|---|
| DNS | hourly/daily |
| CT | near-real-time/daily |
| Public IP/ports | daily/high-risk hourly |
| HTTP fingerprints | daily |
| Critical APIs | daily |
| Cloud inventory | near-real-time/event-driven |
| IAM | daily/event-driven |
| Certificates | daily |
| Git secrets | event-driven |
| Dependencies | daily |
| Containers | per build + daily runtime |
| SaaS | daily/weekly |
| Mobile | release-driven + weekly |
| IoT/OT | controlled scheduled scans |
| AI inventory | event-driven + daily |
| MCP | discovery daily + drift monitoring |
| Critical attack paths | continuous recomputation |

The platform should support both:

```text
scheduled scanning
+
change-triggered scanning
```

---

# 50. Change Detection Is as Important as Vulnerability Detection

Track fingerprints for:

```text
DNS
certificates
ports
services
HTTP headers
HTML
JS
API schemas
tool definitions
MCP resources
cloud configurations
IAM policies
container digests
SBOM
package versions
OAuth permissions
AI model/version
MCP server metadata
```

Then compute:

```text
NEW
REMOVED
MODIFIED
REAPPEARED
MOVED
EXPOSED
NO LONGER EXPOSED
PRIVILEGE EXPANDED
PRIVILEGE REDUCED
```

A new asset is often more interesting than an old low-severity vulnerability.

---

# 51. Shadow IT Detection

Use multiple sources:

```text
DNS
CT
public IP
cloud accounts
SSO
OAuth
browser/application telemetry
Git repositories
mobile apps
SaaS catalogs
certificate names
vendor integrations
```

Correlate ownership using:

```text
company domain
certificate organization
ASN
cloud account metadata
repo organization
email domain
OAuth tenant
branding
DNS naming patterns
```

Output:

```text
Probable company-owned asset
Confidence 0.93
Owner hypothesis: Engineering
Evidence: CT + DNS + GitHub + cloud CNAME
```

---

# 52. Internet Intelligence Sources

Your platform can integrate public data sources such as:

```text
Certificate Transparency
Passive DNS
RDAP/WHOIS
BGP / ASN data
Search engines
Censys
Shodan
GreyNoise
SecurityTrails
Internet scan datasets
Public Git repositories
Public package registries
Cloud public catalogs
```

Censys explicitly maps domains, IPs, certificates and ASN relationships. Microsoft's EASM uses external discovery to surface unknown resources and software/framework details. ProjectDiscovery integrates several internet intelligence services through `uncover`. [Censys](https://docs.censys.com/docs/asm-understand-investigate-attack-surface), [Microsoft EASM](https://www.microsoft.com/en-in/security/business/cloud-security/microsoft-defender-external-attack-surface-management), [ProjectDiscovery uncover via Nuclei docs](https://docs.projectdiscovery.io/opensource/nuclei/running)

---

# 53. Enumeration Pipeline

A practical orchestration pipeline:

```text
INPUT SEEDS
   ↓
PASSIVE DISCOVERY
   ↓
ACTIVE DNS
   ↓
IP / ASN / CERT CORRELATION
   ↓
PORT DISCOVERY
   ↓
SERVICE IDENTIFICATION
   ↓
HTTP PROBING
   ↓
TECHNOLOGY FINGERPRINTING
   ↓
CRAWLING
   ↓
API DISCOVERY
   ↓
AUTHENTICATION-AWARE ENUMERATION
   ↓
CLOUD / SaaS / REPOSITORY CORRELATION
   ↓
VULNERABILITY / MISCONFIGURATION SCAN
   ↓
TARGETED VALIDATION
   ↓
ATTACK GRAPH
```

Run cheap operations first and expensive operations only when triggered by evidence.

---

# 54. Scan Scheduling Logic

Every asset gets a dynamic scan profile.

Example:

```text
PUBLIC + CRITICAL + CHANGES OFTEN
    → frequent scanning

PUBLIC + LOW CHANGE
    → daily/weekly

INTERNAL + HIGH PRIVILEGE
    → authenticated periodic scan

OT/ICS
    → controlled low-impact scan

AI / MCP / agent
    → discovery + semantic + identity tests

EPHEMERAL CLOUD
    → event-driven
```

Use change-triggered escalation:

```text
new subdomain
  → port scan
  → web probe
  → technology scan
  → Nuclei exposure templates
  → API discovery
```

---

# 55. Active Scanning Safety Model

The red-team module should support explicit modes:

```text
PASSIVE
SAFE ACTIVE
AUTHENTICATED VALIDATION
DEEP PENTEST
```

### PASSIVE

No direct traffic beyond data-source access.

### SAFE ACTIVE

Benign probes, fingerprints, protocol checks, canaries and read-only tests.

### AUTHENTICATED VALIDATION

Uses explicitly supplied test identities.

### DEEP PENTEST

Controlled exploit verification in scope, ideally with dedicated test assets, canaries, or rollback mechanisms.

The UI should make the mode impossible to misunderstand.

---

# 56. Red-Team Test Library Architecture

Store tests as metadata-driven modules.

```yaml
id: ASM-WEB-SSRF-001
category: web
name: SSRF destination validation
severity: high
requires_auth: optional
safe_mode: canary
inputs:
  - url_parameter
signals:
  - outbound_interaction
  - private_destination
references:
  - OWASP API7
```

For each test store:

```text
ID
name
category
severity
CWE
OWASP mapping
MITRE mapping
CVE relation
required capability
active/passive
safe/destructive
expected evidence
false-positive guidance
remediation
```

Nuclei's template model is a useful implementation inspiration because templates encode protocol, matchers, extractors, severity and metadata while remaining extensible. [Nuclei templates](https://docs.projectdiscovery.io/templates/structure)

---

# 57. Generic Security Test Categories

Your overall scanner should eventually cover:

```text
AUTH-001 Authentication bypass
AUTH-002 Session weakness
AUTH-003 Token validation
AUTH-004 OAuth misconfiguration
AUTH-005 SSO trust issue
AUTH-006 MFA boundary issue
AUTH-007 Authorization bypass
AUTH-008 Tenant isolation

NET-001 Public service
NET-002 Management service
NET-003 Weak TLS
NET-004 IPv6 exposure
NET-005 DNS issue
NET-006 SSRF
NET-007 DNS rebinding
NET-008 Redirect trust

WEB-001 Injection
WEB-002 Path traversal
WEB-003 File inclusion
WEB-004 Upload abuse
WEB-005 XXE
WEB-006 Deserialization
WEB-007 Request smuggling indicator
WEB-008 CORS
WEB-009 CSRF
WEB-010 Open redirect
WEB-011 Host-header trust

API-001 BOLA
API-002 Broken function auth
API-003 Property auth
API-004 Rate/resource abuse
API-005 Sensitive business flow
API-006 Inventory drift
API-007 Shadow API
API-008 Unsafe third-party consumption

CLOUD-001 Public storage
CLOUD-002 Public database
CLOUD-003 Public management
CLOUD-004 Broad IAM
CLOUD-005 Cross-account trust
CLOUD-006 Metadata access
CLOUD-007 Public snapshot
CLOUD-008 Public registry

SC-001 Dependency CVE
SC-002 KEV dependency
SC-003 Secret
SC-004 Provenance gap
SC-005 Untrusted build
SC-006 Mutable artifact
SC-007 Pipeline injection

DATA-001 Sensitive file
DATA-002 Sensitive endpoint
DATA-003 Public bucket
DATA-004 Search index exposure
DATA-005 Backup exposure

AI-001 Prompt injection
AI-002 Excessive agency
AI-003 Tool authorization
AI-004 RAG poisoning
AI-005 Sensitive information disclosure
AI-006 Model supply chain
AI-007 Agent privilege escalation
AI-008 Cross-agent trust

MCP-001 ... MCP test catalog from this document ...
```

---

# 58. Static Analysis Should Be Taint-Oriented

Static scanners often stop at pattern matching.

A better engine is:

```text
SOURCE
  ↓
UNTRUSTED INPUT
  ↓
VALIDATION
  ↓
TRANSFORMATION
  ↓
CANONICALIZATION
  ↓
AUTHORIZATION
  ↓
SINK
```

Example:

```text
user URL
  ↓
URL validator
  ↓
string transformation
  ↓
redirect
  ↓
HTTP client
```

Flag if the final sink operates on a representation different from the one validated.

This is a generalized detector for future zero-days.

---

# 59. Semantic Security Graph

Add a semantic layer that asks:

```text
Can this asset read?
Can it write?
Can it execute?
Can it impersonate?
Can it egress?
Can it access credentials?
Can it trigger an automation?
Can it influence an agent?
```

Represent capability as vectors:

```text
READ
WRITE
EXECUTE
IMPERSONATE
ADMIN
EGRESS
PERSIST
DISCOVER
```

Then discover dangerous combinations:

```text
READ + EGRESS
READ + EXECUTE
WRITE + EXECUTE
IMPERSONATE + ADMIN
PROMPT_INFLUENCE + EGRESS
PUBLIC + ADMIN
UNTRUSTED_INPUT + EXECUTE
```

---

# 60. Attack Path Examples Your Platform Should Automatically Surface

## Example 1: Public API → cloud data

```text
Internet
 ↓
API
 ↓
BOLA
 ↓
object reference
 ↓
service identity
 ↓
cloud storage
```

## Example 2: Public MCP → secret exfiltration

```text
MCP endpoint
 ↓
tool poisoning
 ↓
agent
 ↓
filesystem read
 ↓
secret
 ↓
HTTP egress
```

## Example 3: Stale cloud resource

```text
DNS
 ↓
old hostname
 ↓
cloud load balancer
 ↓
old service
 ↓
known CVE
```

## Example 4: Supply-chain path

```text
public repository
 ↓
workflow
 ↓
untrusted action
 ↓
CI token
 ↓
cloud role
 ↓
deployment
```

## Example 5: OAuth path

```text
public OAuth app
 ↓
excessive scope
 ↓
user token
 ↓
SaaS API
 ↓
private data
```

---

# 61. Asset Ownership and Attribution

Discovery without attribution creates a giant garbage pile.

For every asset, compute:

```text
owner
team
business unit
environment
application
cloud account
region
vendor
criticality
internet exposure
first seen
last seen
confidence
```

Use evidence:

```text
DNS name
certificate organization
cloud tags
repo ownership
SSO catalog
IP registration
TLS cert
Git metadata
application branding
```

Store the evidence that led to attribution.

---

# 62. Drift Detection

Detect these events:

```text
new public IP
new port
new service
new certificate
new subdomain
new cloud account
new public bucket
new API
new API version
new OAuth grant
new privileged identity
new exposed container
new agent
new MCP server
new tool
new external egress destination
```

And removals:

```text
asset disappeared
certificate revoked
port closed
service removed
identity deleted
public exposure removed
```

A removed vulnerability is useful evidence.
A removed asset is also useful evidence.

---

# 63. Security Metrics

Useful platform-level metrics:

```text
Total assets
Known assets
Unknown assets
Public assets
Internet-reachable ports
Critical services
Shadow IT
New assets / week
Removed assets / week
New certificates
New APIs
Shadow APIs
Critical exposures
Known exploited vulnerabilities
Exploit-prone exposures
Attack paths
High-blast-radius paths
Secrets found
Secrets validated
AI assets
Agent assets
MCP servers
High-risk MCP tools
```

Useful trends:

```text
Mean time to discover
Mean time to validate
Mean time to remediate
Exposure age
Unowned asset rate
Unknown public asset rate
Critical attack-path count
Privilege escalation path count
```

---

# 64. Architecture for Your Tool

A good target architecture is:

```text
                          WEB UI
                            |
                            v
                       API / CONTROL
                            |
          +-----------------+-----------------
          |                 |                 |
          v                 v                 v
      SCAN ENGINE       GRAPH ENGINE      RISK ENGINE
          |                 |                 |
          v                 v                 v
    ORCHESTRATOR         GRAPH DB          FINDINGS
          |
   +------+------+------+------+------+------+------+
   |      |      |      |      |      |      |      |
 DNS    CT     BGP   HTTP   CLOUD   CODE   IDENTITY AI/MCP
   |      |      |      |      |      |      |      |
   +------+------+------+------+------+------+------+
                            |
                            v
                     EVIDENCE STORE
                            |
                            v
                     SIEM / SOAR / TICKETS
```

---

# 65. Recommended Data Stores

Use separate responsibilities.

```text
PostgreSQL
  canonical assets
  ownership
  findings
  scan state
  configuration

Graph DB / graph layer
  relationships
  attack paths
  trust paths
  dependency paths

Object storage
  raw scan evidence
  HTML/JSON responses
  certificates
  SBOMs
  artifacts

Search index
  full-text asset search
  headers
  banners
  technology fingerprints

Time-series
  exposure and metric history
```

A PostgreSQL-backed graph representation can still work for the first version if graph queries are kept disciplined.

---

# 66. Asset Fingerprinting Strategy

Every asset should have a stable fingerprint.

Example:

```text
asset_id = hash(
  normalized_type +
  canonical_identifier +
  owner_scope
)
```

And separately:

```text
state_fingerprint
```

based on:

```text
ports
services
headers
cert
DNS
technology
API schema
cloud config
identity
```

This gives you accurate drift detection.

---

# 67. Evidence-First Findings

Every finding should answer:

```text
WHAT
WHERE
WHY
HOW CONFIRMED
WHAT CAN IT REACH
WHO OWNS IT
WHEN FIRST SEEN
WHEN LAST SEEN
WHAT CHANGED
```

A useful finding should look conceptually like:

```text
Finding: Public Kubernetes API
Asset: api.cluster.example.com
Exposure: Internet
Authentication: Unknown
Service: Kubernetes API
Version: inferred
Related identity: cluster-admin service account
Downstream blast radius: 27 workloads
Confidence: 0.94
Evidence: TLS + protocol fingerprint + cloud inventory
```

---

# 68. What Should Trigger Deep Scanning

Do not scan every endpoint equally.

Escalate when:

```text
new public asset
new technology
new admin interface
new API
new authentication provider
new OAuth application
new cloud identity
new privileged tool
new MCP tool
new server instruction
new certificate
known exploited CVE
high EPSS
public database
public storage
command-execution capability
egress capability
cross-tenant behavior
```

---

# 69. What the Platform Should Learn Over Time

Build a historical model.

The scanner should learn:

```text
normal ports
normal certificates
normal subdomains
normal cloud patterns
normal API versions
normal tool sets
normal service identities
normal SaaS usage
normal agent behavior
```

Then detect:

```text
anomaly
new exposure
unexpected ownership
permission expansion
technology drift
new external dependency
```

This is where ASM becomes proactive instead of being a glorified port scanner with a dashboard.

---

# 70. Priority Roadmap for Your Existing Tool

Given the functionality you already have, I would prioritize development in this order.

## Phase 1: strengthen your existing external ASM

```text
1. DNS / CT / ASN expansion
2. IPv4 + IPv6
3. certificate graph
4. service enumeration
5. virtual-host discovery
6. web crawling
7. API discovery
8. technology fingerprinting
9. vulnerability templates
10. ownership attribution
```

## Phase 2: attack-surface graph

```text
11. canonical asset model
12. relationships
13. historical fingerprints
14. drift detection
15. attack-path graph
16. blast-radius scoring
```

## Phase 3: cloud and identity

```text
17. AWS inventory
18. Azure inventory
19. GCP inventory
20. IAM analysis
21. OAuth / SaaS
22. shadow IT
23. public resource correlation
```

## Phase 4: source and supply chain

```text
24. Git discovery
25. secret scanning
26. SBOM
27. dependency/CVE correlation
28. container scanning
29. IaC scanning
30. provenance/SLSA
```

## Phase 5: AI / MCP

```text
31. AI asset discovery
32. agent discovery
33. MCP discovery
34. MCP protocol scanning
35. MCP identity isolation
36. MRTR
37. Tasks
38. cache isolation
39. tool-chain analysis
40. MCP Apps
```

## Phase 6: autonomous red teaming

```text
41. dynamic test selection
42. attack-path generation
43. safe exploit validation
44. OOB canaries
45. long-horizon agentic testing
46. regression testing
```

---

# 71. Autonomous Red-Team Loop

Eventually the platform can do:

```text
DISCOVER
   ↓
CLASSIFY
   ↓
RANK
   ↓
CHOOSE TEST
   ↓
EXECUTE SAFE PROBE
   ↓
ANALYZE RESULT
   ↓
EXPAND ATTACK PATH
   ↓
RE-RANK
   ↓
TEST NEXT EDGE
```

Example:

```text
Find public API
   ↓
Find OpenAPI
   ↓
Find object endpoint
   ↓
Find authenticated role
   ↓
Test BOLA with test identities
   ↓
Discover data access
   ↓
Map service identity
   ↓
Find cloud role
   ↓
Map reachable storage
   ↓
Validate exposure
```

The system should stop at defined impact boundaries rather than blindly pursuing maximum compromise.

---

# 72. Predicting Vulnerability Classes Before CVEs Exist

The platform should have a research engine.

Inputs:

```text
new protocol feature
new SDK API
new parser
new auth mechanism
new cache behavior
new cloud integration
new AI capability
new execution sink
new extension
```

Then map:

```text
new feature
   ↓
new trust boundary
   ↓
new state
   ↓
new parser
   ↓
new identity context
   ↓
new downstream action
```

Flag combinations with high zero-day potential.

### Strong signals

```text
security-critical feature recently introduced
multiple implementations
rapid SDK adoption
incomplete test coverage
new state machine
new cache layer
new proxy/gateway behavior
new identity mechanism
new serialization format
new capability delegation
```

---

# 73. Research Sources for Zero-Day Prediction

Continuously monitor:

```text
protocol specifications
GitHub issues
GitHub security advisories
SDK release notes
CVE records
NVD
CISA KEV
EPSS
CWE trends
commits touching auth/parser/cache/state
new extension proposals
new attack research
vendor incident reports
```

A particularly useful internal detector is:

```text
commit changes:
  auth
  parser
  cache
  state
  redirect
  DNS
  subprocess
  URL fetch
  deserialization

BUT

test coverage does not change
```

That becomes a research candidate.

---

# 74. High-Value Generic Zero-Day Hypotheses for 2026+

## 1. Identity split-brain

```text
authenticated identity != authorization identity
```

## 2. Validation / sink mismatch

```text
safe validation
→ unsafe transformation
→ dangerous sink
```

## 3. Cache / identity mismatch

```text
cache key != authorization context
```

## 4. Parser differential

```text
edge interprets A
backend interprets B
```

## 5. Ephemeral asset blind spot

```text
asset exists too briefly for inventory
```

## 6. Cross-system capability chain

```text
A read capability
+
B execute/egress capability
=
new attack path
```

## 7. Configuration-as-code execution

```text
configuration
→ package
→ runner
→ privileged execution
```

## 8. Metadata-as-code

```text
registry metadata
→ runtime decision
→ security boundary bypass
```

## 9. Agent autonomy gap

```text
LLM instruction
→ tool
→ identity
→ data
→ external action
```

## 10. State-machine confusion

```text
create
→ authorize
→ update
→ cancel
→ retry
```

The individual transitions may be correct while the overall state machine is insecure.

---

# 75. External Attack Surface Scan Profile

For a domain seed, a sensible pipeline is:

```text
[1] Domain normalization
[2] CT enumeration
[3] passive DNS
[4] active DNS
[5] subdomain permutations
[6] wildcard elimination
[7] CNAME/provider analysis
[8] IP correlation
[9] ASN/prefix correlation
[10] certificate correlation
[11] port discovery
[12] service identification
[13] HTTP probing
[14] virtual-host enumeration
[15] technology fingerprinting
[16] crawling
[17] endpoint/API enumeration
[18] vulnerability scan
[19] auth-aware scan if credentials exist
[20] cloud correlation
[21] ownership attribution
[22] attack-path calculation
[23] historical diff
[24] alerting
```

---

# 76. File/IP/URL Input Mode

Because your current ASM accepts domains/files/IPs, normalize every input into a common seed object.

```json
{
  "seed_type": "domain",
  "value": "example.com",
  "source": "user",
  "scope": "authorized",
  "created_at": "2026-08-29T00:00:00Z"
}
```

Then all discovery engines operate on:

```text
Seed → Candidate Asset → Confirmed Asset
```

A file can contain:

```text
domains
URLs
IPs
CIDRs
ASNs
cloud IDs
repo URLs
MCP endpoints
```

---

# 77. False Positive Management

Do not simply silence findings.

Use:

```text
known asset
known service
approved exception
false positive
not exploitable
compensating control
accepted risk
```

Each suppression should have:

```text
reason
owner
created by
expiry date
scope
related finding
```

Temporary suppression matters because attack surfaces change.

---

# 78. SIEM / SOC Integration

Your existing SIEM integration should receive events, not just vulnerabilities.

Recommended event types:

```text
asset.new
asset.removed
asset.changed
service.new
certificate.new
api.new
api.shadowed
cloud.exposure
identity.changed
secret.discovered
cve.exploitable
kev.exposed
attackpath.created
attackpath.expanded
mcp.server.new
mcp.tool.changed
mcp.authorization.changed
agent.new
ai.endpoint.new
```

Example:

```text
asset.new
asset_type: mcp_server
exposure: internet
authentication: none
capabilities: shell, filesystem, http
risk: critical
```

That is much more actionable for a SOC than a generic “scan completed” event.

---

# 79. Detection and Response Feedback Loop

The ASM tool should consume defender telemetry too.

Potential inputs:

```text
SIEM
EDR
CloudTrail
Azure Activity Log
GCP Audit Logs
WAF
DNS logs
proxy logs
identity logs
GitHub audit
SaaS audit logs
MCP audit logs
agent telemetry
```

Then correlate:

```text
Asset exposure
+
Observed attacker activity
=
confirmed active threat path
```

This pushes the product toward CTEM instead of static ASM.

MITRE's detection strategies for remote services illustrate the value of correlating network traffic, authentication logs and application logs rather than relying on one signal. [MITRE detection strategy](https://attack.mitre.org/detectionstrategies/DET0803/)

---

# 80. Proposed Module Layout

```text
asm/
├── discovery/
│   ├── dns/
│   ├── ct/
│   ├── rdap/
│   ├── bgp/
│   ├── passive_dns/
│   ├── search/
│   ├── github/
│   └── cloud/
│
├── network/
│   ├── portscan/
│   ├── service_probe/
│   ├── tls/
│   └── ipv6/
│
├── web/
│   ├── http_probe/
│   ├── fingerprint/
│   ├── crawler/
│   ├── api/
│   ├── auth/
│   └── websocket/
│
├── cloud/
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   ├── iam/
│   └── attack_paths/
│
├── code/
│   ├── git/
│   ├── secrets/
│   ├── sbom/
│   ├── dependencies/
│   └── provenance/
│
├── ai/
│   ├── inventory/
│   ├── agents/
│   ├── llm/
│   ├── rag/
│   └── redteam/
│
├── mcp/
│   ├── discovery/
│   ├── protocol/
│   ├── auth/
│   ├── isolation/
│   ├── mrtr/
│   ├── tasks/
│   ├── cache/
│   ├── tools/
│   ├── resources/
│   ├── apps/
│   └── semantic/
│
├── intelligence/
│   ├── cve/
│   ├── kev/
│   ├── epss/
│   ├── advisories/
│   └── research_candidates/
│
├── graph/
├── risk/
├── evidence/
├── scheduler/
└── integrations/
    ├── siem/
    ├── soar/
    └── ticketing/
```

---

# 81. Minimum Viable Full-Platform Capability

Before calling the platform “complete”, it should be able to take:

```text
a domain
an IP
a CIDR
an ASN
an organization
an AWS account
an Azure subscription
a GCP project
an organization repo
an MCP endpoint
```

and answer:

```text
What assets belong to it?
Which are public?
Which are newly discovered?
Which technologies are present?
Which vulnerabilities apply?
Which are actually reachable?
Which identities can access them?
Which sensitive data can they reach?
Which tools/agents can invoke them?
Which attack paths connect them?
Which paths have changed since last scan?
```

That is the real definition of end-to-end ASM.

---

# 82. Final Priority List

For your specific project, these are the highest-value additions.

## Immediate

```text
1. Asset graph
2. CT + passive DNS + ASN/BGP discovery
3. IPv6 discovery and testing
4. certificate graph
5. virtual-host discovery
6. API inventory
7. authenticated identity matrix
8. cloud asset correlation
9. ownership attribution
10. attack-path computation
```

## Next

```text
11. secrets + Git history
12. SBOM + dependency graph
13. container/Kubernetes
14. SaaS/OAuth
15. IAM analysis
16. webhook discovery
17. event-driven discovery
18. drift monitoring
19. KEV/EPSS prioritization
20. SIEM/SOAR event model
```

## MCP / AI

```text
21. MCP 2026-07-28 protocol tests
22. cross-principal isolation
23. MRTR
24. Tasks
25. cache isolation
26. tool authorization
27. SSRF normalization
28. OAuth discovery
29. cross-server tool chains
30. MCP Apps
31. AI inventory
32. agent capability graph
33. prompt/dataflow testing
```

## Advanced red team

```text
34. parser differential fuzzing
35. race/state-machine testing
36. safe OOB validation
37. semantic attack-chain generation
38. adaptive scan selection
39. zero-day research engine
40. long-horizon agentic red teaming
```

---

# 83. Core Design Principle

The platform should not primarily ask:

> “Which assets have CVEs?”

It should ask:

> **“What can an attacker discover, reach, authenticate to, influence, execute through, and pivot into from the assets that exist right now?”**

That is the difference between vulnerability scanning and attack-surface intelligence.

For a modern enterprise, the most important object is not the host.

It is the **attack path**.

```text
Asset
  ↓
Exposure
  ↓
Identity
  ↓
Capability
  ↓
Data
  ↓
Action
  ↓
Next asset
```

MCP fits naturally into this model:

```text
MCP Server
  ↓
Tool / Resource / Prompt
  ↓
Agent
  ↓
Identity
  ↓
Downstream capability
  ↓
Data / Execution / Egress
```

And the overall red-team platform becomes:

```text
                    ATTACK SURFACE
                          |
          +---------------+---------------+
          |               |               |
      NETWORK         APPLICATION       IDENTITY
          |               |               |
       CLOUD             API             SaaS
          |               |               |
      CONTAINER        SUPPLY CHAIN      DATA
          |               |               |
          +---------------+---------------+
                          |
                         AI
                          |
                         MCP
                          |
                    AGENTIC SYSTEMS
                          |
                          v
                    ATTACK GRAPH
                          |
                          v
                   CONTINUOUS RED TEAM
```

That is the architecture I would build toward.

---

# 84. Selected Research Sources

## ASM / External Attack Surface

- OWASP Attack Surface Analysis Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
- OWASP WSTG Attack Surface Identification: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Attack_Surface_Identification
- Microsoft Defender EASM: https://www.microsoft.com/en-in/security/business/cloud-security/microsoft-defender-external-attack-surface-management
- Google Mandiant ASM: https://cloud.google.com/security/products/attack-surface-management
- Censys ASM: https://docs.censys.com/docs/asm-understand-investigate-attack-surface
- Censys seeds: https://docs.censys.com/docs/asm-seed-your-attack-surface
- OWASP Amass: https://devguide.owasp.org/en/06-verification/02-tools/02-amass/
- ProjectDiscovery: https://docs.projectdiscovery.io/quickstart

## Network / Remote Services

- MITRE ATT&CK T1133: https://attack.mitre.org/techniques/T1133/
- MITRE ATT&CK T1021: https://attack.mitre.org/techniques/T1021/

## API Security

- OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

## Cloud

- AWS Security Hub Network Scanning: https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/
- AWS Security Hub exposure findings: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html
- AWS IAM Access Analyzer: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html
- Azure Resource Graph: https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- Google Cloud Asset Inventory: https://docs.cloud.google.com/asset-inventory/docs

## Software Supply Chain

- SLSA 1.2: https://slsa.dev/spec/v1.2/
- OSV: https://osv.dev/
- GitHub Secret Security: https://docs.github.com/en/code-security/reference/secret-security
- GitHub Push Protection: https://docs.github.com/en/code-security/concepts/secret-security/push-protection
- OWASP CI/CD Security: https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html
- OWASP IaC Security: https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html
- OWASP Docker Security: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## Mobile / IoT

- OWASP MASVS: https://mas.owasp.org/MASVS/
- OWASP ISVS: https://owasp.org/IoT-Security-Verification-Standard-ISVS/

## AI / Agentic Security

- OWASP GenAI project: https://genai.owasp.org/
- OWASP GenAI LLM Top 10 2026: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- OWASP Agentic Applications Top 10 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Red Teaming Taxonomy: https://genai.owasp.org/resource/solutions-landscape-red-teaming-taxonomy/
- OWASP Secure MCP Server Development: https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- AWS AI Inventory: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-ai-inventory.html

## MCP Protocol / Security

- MCP 2026-07-28 specification: https://blog.modelcontextprotocol.io/posts/2026-07-28/
- MCP 2026-07-28 release candidate: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- MCP Apps: https://modelcontextprotocol.io/extensions/apps/overview
- MCP TypeScript SDK 2026-07-28 migration: https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28
- MCP registry advisories: https://github.com/modelcontextprotocol/registry/security/advisories
- MCP server advisories: https://github.com/modelcontextprotocol/servers/security/advisories

## MCP 2026 Vulnerability Examples

- CVE-2026-25536: https://nvd.nist.gov/vuln/detail/CVE-2026-25536
- CVE-2026-27735: https://nvd.nist.gov/vuln/detail/CVE-2026-27735
- CVE-2026-27825: https://nvd.nist.gov/vuln/detail/CVE-2026-27825
- CVE-2026-27826: https://nvd.nist.gov/vuln/detail/CVE-2026-27826
- CVE-2026-39313: https://nvd.nist.gov/vuln/detail/CVE-2026-39313
- CVE-2026-39885: https://nvd.nist.gov/vuln/detail/CVE-2026-39885
- CVE-2026-40159: https://nvd.nist.gov/vuln/detail/CVE-2026-40159
- CVE-2026-44970: https://nvd.nist.gov/vuln/detail/CVE-2026-44970
- CVE-2026-52869: https://nvd.nist.gov/vuln/detail/CVE-2026-52869
- CVE-2026-52870: https://nvd.nist.gov/vuln/detail/CVE-2026-52870
- CVE-2026-67531: https://nvd.nist.gov/vuln/detail/CVE-2026-67531

## Vulnerability Intelligence

- NVD APIs: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
- CVE Program: https://www.cve.org/
- OSV: https://osv.dev/

## Certificate Transparency

- RFC 9162: https://www.rfc-editor.org/info/rfc9162

---

# 85. Closing Architecture

The end state is a platform that looks conceptually like this:

```text
                        YOUR ASM / RED TEAM PLATFORM
                                      |
          +---------------------------+---------------------------+
          |                           |                           |
      DISCOVERY                    INVENTORY                   TESTING
          |                           |                           |
   +------+------+              +-----+------+             +------+------+
   |      |      |              |     |      |             |      |      |
  DNS    CT    BGP             Cloud  IAM   SaaS          Web   API    MCP
  IP    cert   OSINT           Code   AI    Supply        Net   Auth   Agent
   |      |      |              |     |      |             |      |      |
   +------+------+--------------+-----+------+-------------+------+------+
                                      |
                                  GRAPH MODEL
                                      |
                                      v
                               ATTACK PATH ENGINE
                                      |
                                      v
                               RISK / CONFIDENCE
                                      |
                                      v
                              CONTINUOUS MONITOR
                                      |
                    +-----------------+----------------+
                    |                 |                |
                    v                 v                v
                   SIEM              SOAR           TICKETS
```

The central engineering decision is to make **discovery, enumeration, vulnerability testing, identity analysis, capability mapping and attack-path analysis operate on the same canonical asset graph**.

That gives you a tool that can begin as an ASM scanner and grow into a full red-team intelligence platform without having to rebuild the architecture every time somebody invents another acronym for a thing that already connects to the internet.
