import axios from 'axios'
import type { InternalAxiosRequestConfig } from 'axios'
import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  User,
  DashboardStats,
  ExposureMethodology,
  ExposureProfile,
  ChangeFeedEvent,
  NotableSignal,
  Assessment,
  Asset,
  InventoryAssetList,
  Vulnerability,
  Finding,
  Investigation,
  Notification,
  Report,
  ApiKey,
  Resource,
  PaginatedResponse,
  Scan,
  ScanExecution,
  AssetGraph,
  ExposureEvent,
  ScanProfile,
  CapabilityCatalog,
  OpenSourceToolCatalog,
  AssessmentCreateRequest,
  AssessmentImportResponse,
  AsmImportResponse,
  McpSecurityRun,
  ScanAuthorization,
  ScanComparison,
  OperationsSummary,
  ExecutionPolicy,
  RuntimeStatus,
  RuntimeAdapterState,
  SavedScanProfile,
  ScanSchedule,
  ScanScheduleRun,
  ExecutionPreview,
  RuntimeIntegration,
  StorageStatus,
  RetentionPreview,
  RetentionCleanupResult,
  AuthSession,
  OperationWorkspace,
  OperationWorkspaceCreateRequest,
  OperationTransitionAction,
} from './types'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

type RetryableRequest = InternalAxiosRequestConfig & { _retry?: boolean }
let refreshRequest: Promise<void> | null = null

function clearSession() {
  // Remove tokens left by releases that predated HttpOnly cookie sessions.
  localStorage.removeItem('access_token')
  localStorage.removeItem('refresh_token')
  localStorage.removeItem('user')
}

function cookieValue(name: string): string | undefined {
  return document.cookie.split('; ').find(value => value.startsWith(`${name}=`))?.split('=').slice(1).join('=')
}

async function renewAccessToken(): Promise<void> {
  const csrfToken = cookieValue('csrf_token')

  await axios.post<LoginResponse>(`${API_URL}/api/v1/auth/refresh`, {}, {
    withCredentials: true,
    headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
  })
}

// Cookie-authenticated mutations use a double-submit CSRF token.
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const csrfToken = cookieValue('csrf_token')
    if (csrfToken) config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})

// Response interceptor - handle 401 and 403 (HTTPBearer returns 403 for missing token)
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (typeof window !== 'undefined') {
      const status = error.response?.status
      const request = error.config as RetryableRequest | undefined
      const isAuthEndpoint = request?.url?.includes('/auth/login') || request?.url?.includes('/auth/refresh')

      if (status === 401 && request && !request._retry && !isAuthEndpoint) {
        request._retry = true
        try {
          refreshRequest ||= renewAccessToken().finally(() => {
            refreshRequest = null
          })
          await refreshRequest
          return api(request)
        } catch {
          const csrfToken = cookieValue('csrf_token')
          await axios.post(`${API_URL}/api/v1/auth/logout`, {}, {
            withCredentials: true,
            headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
          }).catch(() => undefined)
          clearSession()
          if (window.location.pathname !== '/login') window.location.href = '/login?reason=session_expired'
          return Promise.reject(error)
        }
      }

      const isAuthFailure = status === 401
      if (isAuthFailure && window.location.pathname !== '/login') {
        clearSession()
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

// Auth
export async function login(data: LoginRequest): Promise<LoginResponse> {
  const response = await api.post<LoginResponse>('/api/v1/auth/login', data)
  if (typeof window !== 'undefined') clearSession()
  return response.data
}

export async function register(data: RegisterRequest): Promise<LoginResponse> {
  const response = await api.post<LoginResponse>('/api/v1/auth/register', data)
  if (typeof window !== 'undefined') clearSession()
  return response.data
}

export async function logout(): Promise<void> {
  if (typeof window !== 'undefined') {
    const csrfToken = cookieValue('csrf_token')
    await axios.post(`${API_URL}/api/v1/auth/logout`, {}, {
      withCredentials: true,
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
    }).catch(() => undefined)
    clearSession()
    window.location.href = '/login'
  }
}

export async function getCurrentUser(): Promise<User> {
  const response = await api.get<User>('/api/v1/auth/me')
  return response.data
}

export async function getScanAuthorizations(): Promise<ScanAuthorization[]> {
  const response = await api.get<ScanAuthorization[]>('/api/v1/settings/scan-authorizations')
  return response.data
}

export async function createScanAuthorization(data: {
  target: string
  authorization_type: ScanAuthorization['authorization_type']
  scope_file?: string
  valid_from?: string
  valid_until?: string
  notes?: string
}): Promise<{ id: string; detail: string }> {
  const response = await api.post('/api/v1/settings/scan-authorizations', data)
  return response.data
}

export async function deleteScanAuthorization(id: string): Promise<void> {
  await api.delete(`/api/v1/settings/scan-authorizations/${id}`)
}

// Dashboard
export async function getDashboardStats(): Promise<DashboardStats> {
  const response = await api.get<DashboardStats>('/api/v1/dashboard/stats')
  return response.data
}

export async function getDashboardTrends(): Promise<{
  findings_trend: { date: string; value: number }[]
  assets_trend: { date: string; value: number }[]
  severity_distribution: Record<string, number>
}> {
  const response = await api.get('/api/v1/dashboard/trends')
  return response.data
}

export async function getDashboardRecentFindings(): Promise<Finding[]> {
  const response = await api.get<Finding[]>('/api/v1/dashboard/recent-findings')
  return response.data
}

export async function getExposureProfile(): Promise<ExposureProfile> {
  const response = await api.get<ExposureProfile>('/api/v1/dashboard/exposure-profile')
  return response.data
}

export async function getExposureMethodology(): Promise<ExposureMethodology> {
  const response = await api.get<ExposureMethodology>('/api/v1/dashboard/methodology')
  return response.data
}

export async function getChangeFeed(limit = 20): Promise<ChangeFeedEvent[]> {
  const response = await api.get<ChangeFeedEvent[]>('/api/v1/dashboard/change-feed', {
    params: { limit },
  })
  return response.data
}

export async function getNotableSignals(limit = 6): Promise<NotableSignal[]> {
  const response = await api.get<NotableSignal[]>('/api/v1/dashboard/notable-signals', {
    params: { limit },
  })
  return response.data
}

// Assessments
export async function getAssessments(params?: {
  page?: number
  page_size?: number
  status?: string
}): Promise<PaginatedResponse<Assessment>> {
  const response = await api.get<PaginatedResponse<Assessment>>('/api/v1/assessments', { params })
  return response.data
}

export async function getAssessment(id: string): Promise<Assessment> {
  const response = await api.get<Assessment>(`/api/v1/assessments/${id}`)
  return response.data
}

export async function createAssessment(data: AssessmentCreateRequest): Promise<Assessment> {
  const response = await api.post<Assessment>('/api/v1/assessments', data)
  return response.data
}

export async function importAssessments(
  file: File,
  options?: {
    default_scan_mode?: 'light' | 'medium' | 'aggressive'
    default_auto_start?: boolean
    default_requested_scans?: string[]
    default_requested_utilities?: string[]
    default_nuclei_tags?: string[]
  }
): Promise<AssessmentImportResponse> {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('default_scan_mode', options?.default_scan_mode || 'medium')
  formData.append('default_auto_start', String(options?.default_auto_start ?? false))
  formData.append('default_requested_scans', (options?.default_requested_scans || []).join(','))
  formData.append('default_requested_utilities', (options?.default_requested_utilities || []).join(','))
  formData.append('default_nuclei_tags', (options?.default_nuclei_tags || []).join(','))

  const response = await api.post<AssessmentImportResponse>('/api/v1/assessments/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return response.data
}

export async function getScanProfiles(targetType = 'domain'): Promise<ScanProfile[]> {
  const response = await api.get<ScanProfile[]>('/api/v1/assessments/scan-profiles', {
    params: { target_type: targetType },
  })
  return response.data
}

export async function getSavedScanProfiles(targetType?: string): Promise<SavedScanProfile[]> {
  const response = await api.get<SavedScanProfile[]>('/api/v1/assessments/saved-scan-profiles', { params: { target_type: targetType } })
  return response.data
}

export async function saveScanProfile(payload: Omit<SavedScanProfile, 'id' | 'version' | 'is_active' | 'created_at'>): Promise<SavedScanProfile> {
  const response = await api.post<SavedScanProfile>('/api/v1/assessments/saved-scan-profiles', payload)
  return response.data
}

export async function getScanSchedules(assessmentId?: string): Promise<ScanSchedule[]> {
  const response = await api.get<ScanSchedule[]>('/api/v1/assessments/schedules', { params: { assessment_id: assessmentId } })
  return response.data
}

export async function getStorageStatus(): Promise<StorageStatus> {
  const response = await api.get<StorageStatus>('/api/v1/settings/storage')
  return response.data
}

export async function updateStoragePolicy(payload: { quota_gb: number; scan_retention_days: number; report_retention_days: number }): Promise<void> {
  await api.put('/api/v1/settings/storage-policy', payload)
}

export async function previewStorageRetention(): Promise<RetentionPreview> {
  const response = await api.get<RetentionPreview>('/api/v1/settings/storage/retention-preview')
  return response.data
}

export async function cleanupStorageRetention(confirmationToken: string): Promise<RetentionCleanupResult> {
  const response = await api.post<RetentionCleanupResult>('/api/v1/settings/storage/retention-cleanup', { confirmation_token: confirmationToken })
  return response.data
}

export async function getAuthSessions(): Promise<AuthSession[]> {
  const response = await api.get<AuthSession[]>('/api/v1/auth/sessions')
  return response.data
}

export async function revokeAuthSession(id: string): Promise<void> {
  await api.delete(`/api/v1/auth/sessions/${id}`)
}

export async function revokeOtherAuthSessions(): Promise<number> {
  const response = await api.post<{ revoked: number }>('/api/v1/auth/sessions/actions/revoke-others')
  return response.data.revoked
}

export async function createScanSchedule(payload: Omit<ScanSchedule, 'id' | 'next_run_at' | 'last_run_at' | 'last_status' | 'last_scan_id' | 'created_at'>): Promise<ScanSchedule> {
  const response = await api.post<ScanSchedule>('/api/v1/assessments/schedules', payload)
  return response.data
}

export async function updateScanSchedule(id: string, payload: Partial<ScanSchedule>): Promise<ScanSchedule> {
  const response = await api.patch<ScanSchedule>(`/api/v1/assessments/schedules/${id}`, payload)
  return response.data
}

export async function deleteScanSchedule(id: string): Promise<void> {
  await api.delete(`/api/v1/assessments/schedules/${id}`)
}

export async function getScanScheduleHistory(id: string): Promise<ScanScheduleRun[]> {
  const response = await api.get<ScanScheduleRun[]>(`/api/v1/assessments/schedules/${id}/history`)
  return response.data
}

export async function previewAssessment(payload: AssessmentCreateRequest): Promise<ExecutionPreview> {
  const response = await api.post<ExecutionPreview>('/api/v1/assessments/execution-preview', payload)
  return response.data
}

export async function getCapabilityCatalog(): Promise<CapabilityCatalog> {
  const response = await api.get<CapabilityCatalog>('/api/v1/assessments/capability-catalog')
  return response.data
}

export async function getToolCatalog(): Promise<OpenSourceToolCatalog> {
  const response = await api.get<OpenSourceToolCatalog>('/api/v1/tools/catalog')
  return response.data
}

export async function getScanExecutions(params?: {
  page?: number
  page_size?: number
  status?: string
  assessment_id?: string
}): Promise<PaginatedResponse<ScanExecution>> {
  const response = await api.get<PaginatedResponse<ScanExecution>>('/api/v1/assessments/scan-executions', { params })
  return response.data
}

export async function getScanExecution(id: string): Promise<ScanExecution> {
  const response = await api.get<ScanExecution>(`/api/v1/assessments/scan-executions/${id}`)
  return response.data
}

export async function retryScanExecution(id: string): Promise<ScanExecution> {
  const response = await api.post<ScanExecution>(`/api/v1/assessments/scan-executions/${id}/retry`)
  return response.data
}

export async function cloneScanRecoveryDraft(id: string): Promise<Assessment> {
  const response = await api.post<Assessment>(`/api/v1/assessments/scan-executions/${id}/clone-draft`)
  return response.data
}

export async function deleteAssessment(id: string): Promise<void> {
  await api.delete(`/api/v1/assessments/${id}`)
}

export async function cancelAssessment(id: string): Promise<Assessment> {
  const response = await api.post<Assessment>(`/api/v1/assessments/${id}/cancel`)
  return response.data
}

// Scans
export async function getScans(assessmentId: string): Promise<Scan[]> {
  const response = await api.get<Scan[]>(`/api/v1/assessments/${assessmentId}/scans`)
  return response.data
}

export async function getOperationsSummary(): Promise<OperationsSummary> {
  const response = await api.get<OperationsSummary>('/api/v1/operations/summary')
  return response.data
}

export async function retryScanIngestion(id: string): Promise<{ status: string; scan_id: string }> {
  const response = await api.post<{ status: string; scan_id: string }>(`/api/v1/assessments/scan-executions/${id}/retry-ingestion`)
  return response.data
}

export async function getOperationWorkspaces(): Promise<OperationWorkspace[]> {
  const response = await api.get<OperationWorkspace[]>('/api/v1/operations/workspaces')
  return response.data
}

export async function createOperationWorkspace(payload: OperationWorkspaceCreateRequest): Promise<OperationWorkspace> {
  const response = await api.post<OperationWorkspace>('/api/v1/operations/workspaces', payload)
  return response.data
}

export async function updateOperationWorkspace(id: string, payload: OperationWorkspaceCreateRequest): Promise<OperationWorkspace> {
  const changes = { ...payload }
  delete changes.status
  const response = await api.patch<OperationWorkspace>(`/api/v1/operations/workspaces/${id}`, changes)
  return response.data
}

export async function transitionOperationWorkspace(id: string, action: OperationTransitionAction, reason?: string): Promise<OperationWorkspace> {
  const response = await api.post<OperationWorkspace>(`/api/v1/operations/workspaces/${id}/transition`, { action, reason })
  return response.data
}

export async function getExecutionPolicy(): Promise<ExecutionPolicy> {
  const response = await api.get<ExecutionPolicy>('/api/v1/settings/execution-policy')
  return response.data
}

export async function updateExecutionPolicy(policy: ExecutionPolicy): Promise<ExecutionPolicy> {
  const response = await api.put<ExecutionPolicy>('/api/v1/settings/execution-policy', policy)
  return response.data
}

export async function getRuntimeStatus(): Promise<RuntimeStatus> {
  const response = await api.get<RuntimeStatus>('/api/v1/settings/runtime-status')
  return response.data
}

export async function getRuntimeIntegrations(): Promise<RuntimeIntegration[]> {
  return (await api.get<RuntimeIntegration[]>('/api/v1/settings/runtime-integrations')).data
}

export async function configureRuntimeIntegration(provider: RuntimeIntegration['provider'], payload: { name: string; url: string; api_key: string }): Promise<void> {
  await api.put(`/api/v1/settings/runtime-integrations/${provider}`, payload)
}

export async function testRuntimeIntegration(provider: RuntimeIntegration['provider']): Promise<RuntimeAdapterState> {
  return (await api.post<RuntimeAdapterState>(`/api/v1/settings/runtime-integrations/${provider}/test`)).data
}

export async function startScan(assessmentId: string): Promise<Assessment> {
  const response = await api.post<Assessment>(`/api/v1/assessments/${assessmentId}/rescan`)
  return response.data
}

export async function importAsmTargets(file: File): Promise<AsmImportResponse> {
  const formData = new FormData()
  formData.append('file', file)
  const response = await api.post<AsmImportResponse>('/api/v1/asm/targets/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return response.data
}

export async function cancelAsmTargetScan(targetId: string): Promise<{ message: string; target_id: string; task_id?: string | null }> {
  const response = await api.post<{ message: string; target_id: string; task_id?: string | null }>(`/api/v1/asm/targets/${targetId}/cancel`)
  return response.data
}

// Assets
export async function getAssets(params?: {
  page?: number
  page_size?: number
  type?: string
  status?: string
  assessment_id?: string
  search?: string
  root_domain?: string
  owner?: string
  ownership_status?: string
}): Promise<PaginatedResponse<Asset>> {
  const mappedParams = {
    ...params,
    asset_type: params?.type,
    is_live: params?.status === 'live' ? true : params?.status === 'dead' ? false : undefined,
  }
  const response = await api.get<PaginatedResponse<Asset>>('/api/v1/assets', { params: mappedParams })
  return response.data
}

export async function getAssetInventory(): Promise<InventoryAssetList> {
  const response = await api.get<InventoryAssetList>('/api/v1/assets/inventory')
  return response.data
}

export async function getAssetGraph(params?: { assessment_id?: string; scan_id?: string }): Promise<AssetGraph> {
  const response = await api.get<AssetGraph>('/api/v1/assets/graph', { params })
  return response.data
}

export async function getAssetDrift(params?: {
  assessment_id?: string
  scan_id?: string
  event_type?: string
  page?: number
  page_size?: number
}): Promise<PaginatedResponse<ExposureEvent>> {
  const response = await api.get<PaginatedResponse<ExposureEvent>>('/api/v1/assets/drift', { params })
  return response.data
}

export async function getAsset(id: string): Promise<Asset> {
  const response = await api.get<Asset>(`/api/v1/assets/${id}`)
  return response.data
}

// Vulnerabilities
export async function getVulnerabilities(params?: {
  page?: number
  page_size?: number
  severity?: string
  is_kev?: boolean
  exploit_available?: boolean
  search?: string
}): Promise<PaginatedResponse<Vulnerability>> {
  const response = await api.get<PaginatedResponse<Vulnerability>>('/api/v1/vulnerabilities', {
    params,
  })
  return response.data
}

export async function getVulnerability(id: string): Promise<Vulnerability> {
  const response = await api.get<Vulnerability>(`/api/v1/vulnerabilities/${id}`)
  return response.data
}

// Findings
export async function getFindings(params?: {
  page?: number
  page_size?: number
  severity?: string
  status?: string
  assessment_id?: string
  scan_id?: string
  asset_id?: string
  asset_query?: string
  source?: string
  search?: string
  has_url?: boolean
  min_risk_score?: number
  min_confidence?: number
  reachability?: string
  exploitability?: string
  suppression_active?: boolean
}): Promise<PaginatedResponse<Finding>> {
  const response = await api.get<PaginatedResponse<Finding>>('/api/v1/findings', { params })
  return response.data
}

export async function getFinding(id: string): Promise<Finding> {
  const response = await api.get<Finding>(`/api/v1/findings/${id}`)
  return response.data
}

export interface AuditLogEntry {
  id: string
  action: string
  entity_type?: string | null
  entity_id?: string | null
  actor?: string | null
  ip_address?: string | null
  success: boolean
  details: Record<string, unknown>
  created_at: string
}

export async function getAuditLogs(params?: {
  action?: string
  entity_type?: string
  search?: string
  success?: boolean
  page?: number
  page_size?: number
}): Promise<PaginatedResponse<AuditLogEntry>> {
  const response = await api.get<PaginatedResponse<AuditLogEntry>>('/api/v1/settings/audit-logs', { params })
  return response.data
}

export async function exportAuditLogs(params?: { action?: string; entity_type?: string; search?: string; success?: boolean }): Promise<void> {
  const response = await api.get('/api/v1/settings/audit-logs/export', { params, responseType: 'blob' })
  const href = URL.createObjectURL(response.data)
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = 'audit-log.csv'
  anchor.click()
  URL.revokeObjectURL(href)
}

export async function updateFindingStatus(
  id: string,
  payload: { status: string; notes?: string; scope?: string; expires_at?: string }
): Promise<Finding> {
  const response = await api.patch<Finding>(`/api/v1/findings/${id}/status`, payload)
  return response.data
}

export async function getFindingActivities(id: string): Promise<import('./types').FindingActivity[]> {
  const response = await api.get<import('./types').FindingActivity[]>(`/api/v1/findings/${id}/activities`)
  return response.data
}

export async function createFindingActivity(id: string, payload: {
  activity_type: 'comment' | 'retest_requested' | 'approval_requested' | 'approval_decision'
  body?: string
  payload?: Record<string, unknown>
}): Promise<import('./types').FindingActivity> {
  const response = await api.post<import('./types').FindingActivity>(`/api/v1/findings/${id}/activities`, payload)
  return response.data
}

export async function updateFindingWorkflow(id: string, payload: {
  assigned_to?: string | null
  due_at?: string | null
  verification_status?: Finding['verification_status']
  comment?: string
}): Promise<Finding> {
  const response = await api.patch<Finding>(`/api/v1/findings/${id}/workflow`, payload)
  return response.data
}

// Investigations
export async function getInvestigations(params?: {
  page?: number
  page_size?: number
  status?: string
}): Promise<Investigation[]> {
  const response = await api.get<Investigation[] | PaginatedResponse<Investigation>>('/api/v1/investigations', {
    params,
  })
  const data = response.data
  return Array.isArray(data) ? data : data.items
}

export async function getInvestigation(id: string): Promise<Investigation> {
  const response = await api.get<Investigation>(`/api/v1/investigations/${id}`)
  return response.data
}

export async function createInvestigation(data: Partial<Investigation>): Promise<Investigation> {
  const response = await api.post<Investigation>('/api/v1/investigations', data)
  return response.data
}

export async function deleteInvestigation(id: string): Promise<void> {
  await api.delete(`/api/v1/investigations/${id}`)
}

// Notifications
export async function getNotifications(params?: {
  page?: number
  is_read?: boolean
}): Promise<PaginatedResponse<Notification>> {
  const response = await api.get<PaginatedResponse<Notification>>('/api/v1/notifications', {
    params,
  })
  return response.data
}

export async function markNotificationRead(id: string): Promise<void> {
  await api.patch(`/api/v1/notifications/${id}/read`)
}

export async function markAllNotificationsRead(): Promise<void> {
  await api.post('/api/v1/notifications/read-all')
}

// Reports
export async function getReports(params?: {
  assessment_id?: string
}): Promise<Report[]> {
  const response = await api.get<Report[]>('/api/v1/reports', { params })
  return response.data
}

export async function generateReport(data: {
  assessment_id: string
  format: string
  title?: string
  scan_id?: string
  baseline_scan_id?: string
  asset_ids?: string[]
  severities?: string[]
  statuses?: string[]
  owners?: string[]
  modules?: string[]
}): Promise<Report> {
  const response = await api.post<Report>('/api/v1/reports/generate', data)
  return response.data
}

export async function compareScans(currentScanId: string, baselineScanId: string): Promise<ScanComparison> {
  const response = await api.get<ScanComparison>('/api/v1/reports/compare', {
    params: { current_scan_id: currentScanId, baseline_scan_id: baselineScanId },
  })
  return response.data
}

export async function downloadReport(report: Report): Promise<void> {
  return downloadReportArtifact(report.id, report.filename || report.title)
}

export async function downloadReportArtifact(id: string, filename: string): Promise<void> {
  const response = await api.get<Blob>(`/api/v1/reports/${id}/download`, { responseType: 'blob' })
  const url = URL.createObjectURL(response.data)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export async function deleteReport(id: string): Promise<void> {
  await api.delete(`/api/v1/reports/${id}`)
}

export async function cancelReport(id: string): Promise<Report> {
  const response = await api.post<Report>(`/api/v1/reports/${id}/cancel`)
  return response.data
}

// Settings
export async function getApiKeys(): Promise<ApiKey[]> {
  const response = await api.get<ApiKey[]>('/api/v1/settings/api-keys')
  return response.data
}

export async function saveApiKey(data: {
  name: string
  service: string
  key: string
}): Promise<ApiKey> {
  const response = await api.post<ApiKey>('/api/v1/settings/api-keys', {
    name: data.name,
    key_name: data.service,
    value: data.key,
  })
  return response.data
}

export async function deleteApiKey(id: string): Promise<void> {
  await api.delete(`/api/v1/settings/api-keys/${id}`)
}

export async function getUsers(): Promise<User[]> {
  const response = await api.get<User[]>('/api/v1/settings/users')
  return response.data
}

// Resources
export async function getResources(params?: {
  category?: string
  search?: string
}): Promise<PaginatedResponse<Resource>> {
  const response = await api.get<PaginatedResponse<Resource>>('/api/v1/resources', { params })
  return response.data
}

export async function toggleResourceFavorite(id: string): Promise<{ is_favorite: boolean }> {
  const response = await api.post<{ is_favorite: boolean }>(`/api/v1/resources/${id}/favorite`)
  return response.data
}

// AI Chat
export async function sendChatMessage(message: string): Promise<{ response: string }> {
  const response = await api.post<{ response: string }>('/api/v1/ai/chat', { message })
  return response.data
}

// Security Toolkit
export async function toolDnsLookup(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/dns', { target })
  return response.data
}

export async function toolWhois(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/whois', { target })
  return response.data
}

export async function toolSslCheck(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/ssl', { target })
  return response.data
}

export async function toolCrtsh(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/crtsh', { target })
  return response.data
}

export async function toolWayback(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/wayback', { target })
  return response.data
}

export async function toolHeadersCheck(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/headers', { target })
  return response.data
}

export async function toolShodan(target: string): Promise<any> {
  const response = await api.post('/api/v1/tools/shodan', { target })
  return response.data
}

export async function getMcpSecurityRuns(): Promise<{ items: McpSecurityRun[]; total: number }> {
  const response = await api.get('/api/v1/mcp-security/runs')
  return response.data
}

export async function createMcpSecurityRun(data: {
  name: string
  endpoint: string
  bearer_token?: string
  allow_private: boolean
  protocol_tests: boolean
  authorization_confirmed: boolean
  secondary_bearer_token?: string
  audience_mismatch_token?: string
  issuer_mismatch_token?: string
  approved_tool_name?: string
  approved_tool_arguments?: Record<string, unknown>
  approved_resource_uri?: string
  approved_prompt_name?: string
  test_task_id?: string
  canary_url?: string
  cross_server_endpoint?: string
  cross_server_bearer_token?: string
  local_config_text?: string
  max_concurrency?: number
  enable_deep_tests?: boolean
  allow_mutation_tests?: boolean
  deep_authorization_confirmed?: boolean
}): Promise<McpSecurityRun> {
  const response = await api.post<McpSecurityRun>('/api/v1/mcp-security/runs', data)
  return response.data
}

export async function getMcpSecurityRun(id: string): Promise<McpSecurityRun> {
  const response = await api.get<McpSecurityRun>(`/api/v1/mcp-security/runs/${id}`)
  return response.data
}

export async function cancelMcpSecurityRun(id: string): Promise<McpSecurityRun> {
  const response = await api.post<McpSecurityRun>(`/api/v1/mcp-security/runs/${id}/cancel`)
  return response.data
}

export async function deleteMcpSecurityRun(id: string): Promise<void> {
  await api.delete(`/api/v1/mcp-security/runs/${id}`)
}
