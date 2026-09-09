export interface User {
  id: string
  username: string
  email: string
  full_name: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  created_at: string
  last_login: string | null
  avatar_url?: string
}

export interface Organization {
  id: string
  name: string
  slug: string
  created_at: string
  members: User[]
}

export interface Assessment {
  id: string
  name: string
  description?: string | null
  target: string
  target_type: 'domain' | 'ip' | 'cidr' | 'url' | 'api' | 'file' | 'asn' | 'repository' | 'image' | 'kubernetes' | 'android' | 'ios' | 'cloud_account' | 'organization' | 'mcp'
  status: 'created' | 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  scan_mode: 'light' | 'medium' | 'aggressive'
  phases: Record<string, boolean> | string[]
  flags: AssessmentFlags
  risk_score: number | null
  created_at: string
  updated_at: string
  completed_at: string | null
  created_by: string
  findings_count?: number
  assets_count?: number
  organization_id?: string
  org_id?: string
  is_demo?: boolean
}

export interface AssessmentCreateRequest {
  name: string
  description?: string
  target: string
  target_type: Assessment['target_type']
  scan_mode: Assessment['scan_mode']
  phases: Record<string, boolean>
  flags: AssessmentFlags
  auto_start?: boolean
  requested_scans?: string[]
  requested_utilities?: string[]
  nuclei_tags?: string[]
  imported_targets?: ImportedAssessmentTarget[]
}

export interface ImportedAssessmentTarget {
  name: string
  target: string
  target_type: 'domain' | 'ip' | 'cidr' | 'url' | 'api' | 'file' | 'asn' | 'repository' | 'image' | 'kubernetes' | 'android' | 'ios' | 'cloud_account' | 'organization' | 'mcp'
  description?: string | null
  tags?: string[]
  raw?: Record<string, string>
  requested_scans?: string[]
  requested_utilities?: string[]
  nuclei_tags?: string[]
  scan_mode?: 'light' | 'medium' | 'aggressive'
  auto_start?: boolean
  canonical_key?: string
  root_domain?: string | null
  parent_key?: string | null
}

export interface AssessmentImportResponse {
  added: number
  skipped: number
  errors: string[]
  imported_targets: ImportedAssessmentTarget[]
  suggested_name?: string | null
  suggested_description?: string | null
}

export interface AssessmentFlags {
  passive_only: boolean
  stealth: boolean
  screenshots: boolean
  cve: boolean
  crawl: boolean
  agent: boolean
  no_osint: boolean
  diff: boolean
  baseline: boolean
  allow_active_validation?: boolean
  proxy?: string
}

export interface ScanProfile {
  mode: Assessment['scan_mode']
  label: string
  description: string
  target_type: Assessment['target_type'] | 'domain'
  phases: Record<string, boolean>
  flags: AssessmentFlags
  utilities: string[]
  nuclei_tags: string[]
  business_logic: string
  pipeline: string[]
  scan_strategy: string
  readiness: Record<string, string>
  tool_plan: ToolPlanItem[]
}

export interface SavedScanProfile {
  id: string
  name: string
  description?: string | null
  target_type: Assessment['target_type']
  scan_mode: Assessment['scan_mode']
  version: number
  configuration: Record<string, unknown>
  is_active: boolean
  created_at: string
}

export interface ScanSchedule {
  id: string
  assessment_id: string
  name: string
  timezone: string
  interval_minutes: number
  window_start?: string | null
  window_end?: string | null
  missed_run_policy: 'run_once' | 'skip'
  overlap_policy: 'skip'
  is_active: boolean
  next_run_at: string
  last_run_at?: string | null
  last_status?: string | null
  last_scan_id?: string | null
  created_at: string
}

export interface ScanScheduleRun {
  id: string
  scan_id?: string | null
  planned_at: string
  status: string
  message?: string | null
  created_at: string
}

export interface ExecutionPreview {
  target_type: string
  target_count: number
  scan_mode: string
  phases: Record<string, boolean>
  flags: Record<string, unknown>
  tool_plan: ToolPlanItem[]
  execution_manifest: Array<Record<string, unknown>>
  execution_policy: Record<string, unknown>
  authorization: Record<string, unknown>
  estimated_seconds: number
  warnings: string[]
  template_plan: Record<string, unknown>
  wordlist_plan: Record<string, unknown>
  adapter_prerequisites: Array<Record<string, unknown>>
  safety_controls: string[]
  exclusions: string[]
  confidence: string
}

export interface ToolPlanItem {
  tool_id: string
  name: string
  role: string
  required: boolean
  status: string
  bundled: boolean
  install_mode: string
  outputs: string[]
  execution?: string
  safety_tier?: string
  prerequisites?: string[]
  confidence?: string
}

export interface PlatformCapability {
  id: string
  name: string
  blueprint_sections: string[]
  status: 'operational' | 'conditional' | 'partial' | 'integration_required' | 'research'
  execution: string
  safety_tier: string
  outputs: string[]
  prerequisites: string[]
}

export interface CapabilityCatalog {
  source: string
  version: string
  status_definitions: Record<string, string>
  counts: Record<string, number>
  document_coverage: {
    actionable_sections: number
    mapped_sections: number
    unmapped_sections: string[]
    reference_only_sections: string[]
  }
  capabilities: PlatformCapability[]
}

export interface OpenSourceScanner {
  id: string
  name: string
  category: string
  license: string
  status: string
  install_mode: string
  target_types: string[]
  outputs: string[]
  execution: string
  notes: string
  bundled: boolean
}

export interface OpenSourceToolCatalog {
  version: string
  counts: {
    total: number
    by_category: Record<string, number>
    by_status: Record<string, number>
  }
  scanners: OpenSourceScanner[]
}

export interface Scan {
  id: string
  assessment_id: string
  celery_task_id?: string | null
  session_dir?: string | null
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  current_phase?: string | null
  started_at: string | null
  completed_at: string | null
  heartbeat_at?: string | null
  cancel_requested_at?: string | null
  attempt?: number
  max_attempts?: number
  error_message: string | null
  raw_log?: string | null
  scan_metadata?: Record<string, unknown> | null
  progress: number
}

export interface ScanExecution extends Scan {
  assessment_name: string
  target: string
  target_type: Assessment['target_type']
  scan_mode: Assessment['scan_mode']
  events?: ScanEvent[]
  tool_runs?: ScanToolRun[]
  artifacts?: ScanArtifact[]
}

export interface ScanArtifact {
  id: string
  path: string
  artifact_type: string
  mime_type?: string | null
  size_bytes: number
  sha256: string
  retained: boolean
  provenance: Record<string, unknown>
}

export interface ScanEvent {
  id: string
  event_type: string
  status?: string | null
  phase?: string | null
  progress?: number | null
  message?: string | null
  payload: Record<string, unknown>
  created_at: string
}

export interface ScanToolRun {
  id: string
  external_id: string
  tool: string
  tool_version?: string | null
  status: string
  exit_code?: number | null
  command?: string | null
  output_file?: string | null
  output_excerpt?: string | null
  started_at?: string | null
  completed_at?: string | null
  duration_ms?: number | null
  provenance: Record<string, unknown>
}

export interface AsmImportResponse {
  added: number
  skipped: number
  errors: string[]
}

export interface Asset {
  id: string
  assessment_id: string
  value: string
  type: 'domain' | 'subdomain' | 'ip' | 'url' | 'cidr' | 'image' | 'cloud_resource'
  status: 'live' | 'dead' | 'unknown'
  first_seen: string
  last_seen: string
  technologies: Technology[]
  ports: Port[]
  dns_records: DnsRecord[]
  tls_certificate: TlsCertificate | null
  findings_count: number
  risk_score: number
  metadata: Record<string, unknown>
  canonical_key?: string | null
  normalized_value?: string | null
  root_domain?: string | null
  owner?: string | null
  ownership_status?: string
  related_count?: number
  asm_related_count?: number
}

export interface InventoryRelation {
  source_key: string
  target_key: string
  relation: string
}

export interface InventoryAsset {
  canonical_key: string
  normalized_value: string
  primary_type: string
  hostname?: string | null
  root_domain?: string | null
  related_keys: string[]
  assessment_ids: string[]
  asm_target_ids: string[]
  assessment_asset_ids: string[]
  source_types: string[]
  values: string[]
  statuses: Record<string, number>
  metadata: Record<string, unknown>
}

export interface AssetGraphNode {
  id: string
  canonical_key?: string | null
  type: string
  label: string
  is_live: boolean
  owner?: string | null
  ownership_status: string
}

export interface AssetGraphEdge {
  id: string
  source: string
  target: string
  relation: string
  confidence: number
  evidence: Record<string, unknown>
}

export interface AttackPath {
  id: string
  scan_id: string
  title: string
  severity: string
  risk_score: number
  status: string
  nodes: Array<Record<string, unknown>>
  edges: Array<Record<string, unknown>>
  evidence?: string | null
}

export interface AssetGraph {
  nodes: AssetGraphNode[]
  edges: AssetGraphEdge[]
  attack_paths: AttackPath[]
}

export interface ExposureEvent {
  id: string
  assessment_id: string
  scan_id?: string | null
  asset_id?: string | null
  event_type: string
  severity: string
  payload: Record<string, unknown>
  observed_at: string
}

export interface InventoryAssetList {
  items: InventoryAsset[]
  relations: InventoryRelation[]
  total: number
}

export interface DnsRecord {
  id: string
  asset_id: string
  record_type: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'SOA' | 'CAA' | 'CNAME' | 'PTR' | 'SRV'
  name: string
  value: string
  ttl: number
  priority?: number
}

export interface Port {
  id: string
  asset_id: string
  port_number: number
  protocol: 'tcp' | 'udp'
  state: 'open' | 'closed' | 'filtered'
  service: string
  version: string
  banner: string
  product: string
}

export interface Technology {
  id: string
  name: string
  version: string
  category: string
  confidence: number
  icon?: string
}

export interface TlsCertificate {
  id: string
  asset_id: string
  subject: string
  issuer: string
  serial_number: string
  not_before: string
  not_after: string
  days_until_expiry: number
  key_algorithm: string
  key_size: number
  signature_algorithm: string
  san: string[]
  is_expired: boolean
  is_self_signed: boolean
  grade: string
  issues: string[]
}

export interface Vulnerability {
  id: string
  cve_id: string
  title: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  cvss_score: number
  cvss_vector: string
  epss_score: number
  epss_percentile: number
  is_kev: boolean
  kev_date_added?: string
  affected_assets: string[]
  affected_assets_count: number
  references: string[]
  published_date: string
  modified_date: string
  cwe_id: string
  cwe_name: string
  remediation: string
  exploit_available: boolean
}

export interface Finding {
  id: string
  assessment_id: string
  asset_id: string
  asset_value: string
  title: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  category: string
  source: string
  template_id: string
  cve_id: string | null
  cvss_score: number | null
  evidence: string
  remediation: string
  status: 'open' | 'new' | 'confirmed' | 'false_positive' | 'remediated' | 'accepted' | 'suppressed' | 'approved_exception' | 'accepted_risk' | 'compensating_control' | 'not_exploitable'
  risk_score?: number | null
  confidence_score?: number | null
  reachability?: string | null
  exploitability?: string | null
  evidence_metadata?: Record<string, unknown>
  status_reason?: string | null
  status_scope?: string | null
  suppression_expires_at?: string | null
  assigned_to?: string | null
  due_at?: string | null
  sla_status?: 'untracked' | 'on_track' | 'overdue'
  verification_status?: 'not_requested' | 'requested' | 'in_progress' | 'passed' | 'failed' | 'inconclusive'
  first_seen?: string | null
  found_at: string
  confirmed_at: string | null
  url: string | null
  matched_at: string | null
  matcher_name: string | null
  curl_command: string | null
  reference: string[]
}

export interface FindingActivity {
  id: string
  finding_id: string
  actor_id?: string | null
  activity_type: string
  body?: string | null
  payload: Record<string, unknown>
  created_at: string
}

export interface Investigation {
  id: string
  title: string
  description: string
  status: 'open' | 'in_progress' | 'closed' | 'archived'
  priority: 'critical' | 'high' | 'medium' | 'low'
  findings: string[]
  findings_count: number
  notes: InvestigationNote[]
  created_at: string
  updated_at: string
  created_by: string
  assignee: string | null
  tags: string[]
  mitre_techniques: string[]
}

export interface InvestigationNote {
  id: string
  content: string
  created_at: string
  created_by: string
}

export interface Resource {
  id: string
  name: string
  description: string
  url: string
  category: string
  subcategory: string
  tags: string[]
  is_favorite: boolean
  integration_status: 'integrated' | 'available' | 'external'
}

export interface Notification {
  id: string
  title: string
  message: string
  type: 'info' | 'warning' | 'error' | 'success'
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  is_read: boolean
  created_at: string
  link: string | null
  source: string
}

export interface DashboardStats {
  total_assets: number
  total_domains: number
  total_vulnerabilities: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  info_findings: number
  risk_score: number
  active_scans: number
  completed_scans: number
  assets_change_percent: number
  vulns_change_percent: number
  severity_breakdown: SeverityBreakdown[]
  vuln_trend: VulnTrendPoint[]
  recent_findings: Finding[]
  recent_activity: ActivityItem[]
  top_risks: Finding[]
}

export interface ExposureCategory {
  key: string
  label: string
  weight: number
  score: number
  summary: string
}

export interface ExposureProfile {
  profile_name: string
  org_id: string
  external_footprint: Record<string, number>
  overall_score: number
  posture_tier: string
  confidence: string
  notable_signal: string
  last_observed: string
  categories: ExposureCategory[]
}

export interface MethodologyCategory {
  key: string
  label: string
  weight: number
  summary: string
  evidence_sources: string[]
}

export interface ExposureMethodology {
  title: string
  description: string
  categories: MethodologyCategory[]
}

export interface ChangeFeedEvent {
  id: string
  event_type: string
  title: string
  detail: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  timestamp: string
  href?: string | null
}

export interface NotableSignal {
  id: string
  title: string
  detail: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  source: string
  timestamp?: string | null
}

export interface SeverityBreakdown {
  name: string
  value: number
  color: string
}

export interface VulnTrendPoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface ActivityItem {
  id: string
  type: 'scan_started' | 'scan_completed' | 'finding_new' | 'finding_confirmed' | 'asset_discovered'
  title: string
  description: string
  timestamp: string
  severity?: string
  icon?: string
}

export interface Report {
  id: string
  assessment_id: string
  title: string
  format: 'markdown' | 'html' | 'pdf' | 'sarif' | 'csv' | 'json' | 'evidence'
  status: 'generating' | 'ready' | 'failed' | 'cancelled'
  created_at: string
  file_size: number
  download_url?: string | null
  error?: string | null
  filename?: string
  version?: number
  sha256?: string
  scope?: Record<string, unknown>
}

export interface ScanComparison {
  assessment_id: string
  current_scan_id: string
  baseline_scan_id: string
  summary: { new: number; resolved: number; unchanged: number; changed: number }
  new: Array<Record<string, unknown>>
  resolved: Array<Record<string, unknown>>
  changed: Array<Record<string, unknown>>
  unchanged: number
}

export interface OperationsSummary {
  generated_at: string
  scans: Record<string, number>
  stale_active_scans: number
  queue_depths: Record<string, number | null>
  deployment: {
    scan_executor: string
    artifact_storage: string
    mobile_dynamic: boolean
    kubernetes_runtime: boolean
  }
  capacity: {
    max_active_scans: number
    max_queued_scans: number
    active_available: number
    queued_available: number
    priority: number
  }
  workers: Array<{
    name: string
    status: 'online' | 'stale'
    image_identity: string
    queues: string[]
    capabilities: string[]
    versions: Record<string, string>
    last_seen_at: string
  }>
}

export interface ExecutionPolicy {
  max_active_scans: number
  max_queued_scans: number
  priority: number
  settings: Record<string, unknown>
}

export interface RuntimeAdapterState {
  configured: boolean
  healthy: boolean | null
  message?: string
  status_code?: number
  mode?: string
  backend?: string
}

export interface RuntimeStatus {
  scan_executor: RuntimeAdapterState
  artifact_storage: RuntimeAdapterState
  mobile_dynamic: RuntimeAdapterState
  kubernetes_runtime: RuntimeAdapterState
  cspm: RuntimeAdapterState
  monitoring: RuntimeAdapterState
  required_variables: Record<string, string[]>
}

export interface StorageStatus {
  used_bytes: number
  quota_bytes: number
  usage_percent: number
  scan_artifacts: { count: number; bytes: number }
  reports: { count: number; bytes: number }
  retention: { scan_days: number; report_days: number }
  backend: string
  cache_accounting: string
}

export interface RetentionPreview {
  scan_retention_days: number
  report_retention_days: number
  scan_artifacts: { count: number; bytes: number }
  reports: { count: number; bytes: number }
  reclaimable_bytes: number
  confirmation_token: string
  expires_in_seconds: number
}

export interface RetentionCleanupResult {
  scan_artifacts_released: number
  reports_deleted: number
  errors: string[]
}

export interface AuthSession {
  id: string
  device_name: string
  ip_address?: string | null
  created_at: string
  last_used_at?: string | null
  expires_at: string
  revoked_at?: string | null
  is_current: boolean
  is_active: boolean
}

export interface RuntimeIntegration {
  id: string
  provider: 'mobile_dynamic' | 'kubernetes_runtime'
  name: string
  is_active: boolean
  configured: boolean
  last_status?: string | null
  last_error?: string | null
  last_used_at?: string | null
}

export interface ApiKey {
  id: string
  name: string
  key_preview: string
  service: string
  is_valid: boolean
  created_at: string
  last_used: string | null
}

export interface ScanAuthorization {
  id: string
  target: string
  authorization_type: 'full' | 'passive_only' | 'read_only'
  authorized_by: string
  scope_file?: string | null
  valid_from?: string | null
  valid_until?: string | null
  notes?: string | null
  created_at: string
}

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: string
  tool_calls?: ToolCall[]
}

export interface ToolCall {
  tool: string
  args: Record<string, unknown>
  result: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  access_token: string
  refresh_token?: string | null
  token_type: string
  expires_in: number
  refresh_expires_in: number
}

export interface RegisterRequest {
  username: string
  email: string
  password: string
  organization_name?: string
}

export interface McpFinding {
  id: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  title: string
  category: string
  evidence: string
  remediation: string
  exchange_id?: string | null
  test_id?: string | null
}

export interface McpExchange {
  id: string
  name: string
  request: { method: string; url: string; headers: Record<string, string>; body: unknown }
  response: { status: number | null; headers: Record<string, string>; header_values?: Record<string, string[]>; body: unknown; error?: string | null }
  duration_ms: number
}

export interface McpSecurityRun {
  id: string
  name: string
  endpoint: string
  status: 'queued' | 'running' | 'cancel_requested' | 'cancelled' | 'completed' | 'failed'
  overall_severity: McpFinding['severity']
  risk_score: number
  summary: { counts?: Record<string, number>; tools?: number; resources?: number; resource_templates?: number; prompts?: number; exchanges?: number; checks?: Record<string, number>; test_coverage?: Record<string, number>; canonical_tests?: number; progress?: number; current_step?: string; completed_steps?: number; estimated_steps?: number; task_id?: string }
  inventory: {
    server?: Record<string, unknown>
    protocol_version?: string | null
    capabilities?: Record<string, unknown>
    tools?: Array<Record<string, unknown>>
    resources?: Array<Record<string, unknown>>
    resource_templates?: Array<Record<string, unknown>>
    prompts?: Array<Record<string, unknown>>
    instructions?: string | null
    oauth_metadata_published?: boolean
    cache_hints?: Record<string, unknown>
    oauth_metadata?: Record<string, unknown>
    execution_profile?: Record<string, unknown>
    local_config_analysis?: Record<string, unknown>
    recommended_manual_tests?: string[]
    negotiation?: {
      selected_protocol?: string | null
      fallback_reason?: string | null
      discover_supported_versions?: string[]
    }
    tool_fingerprint?: string
    protocol_checks?: Array<{
      id: string
      name: string
      status: 'passed' | 'failed' | 'review' | 'informational'
      detail: string
      http_status?: number | null
      duration_ms: number
      test_id?: string | null
    }>
    test_coverage?: Array<{
      test_id: string
      title: string
      status: 'executed' | 'failed' | 'review' | 'blocked' | 'not_applicable'
      mode: string
      checks: string[]
      reason?: string | null
      evidence?: unknown
    }>
  }
  findings: McpFinding[]
  exchanges: McpExchange[]
  error_message?: string | null
  created_at: string
  completed_at?: string | null
}
