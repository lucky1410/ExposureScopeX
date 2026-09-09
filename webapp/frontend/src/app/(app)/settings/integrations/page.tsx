'use client'

import { useCallback, useEffect, useState } from 'react'
import {
  Bell, Database, GitBranch, Shield, Server, Zap, Bug,
  Cloud, CheckCircle2, XCircle, AlertCircle, ChevronDown,
  ChevronUp, Loader2, RefreshCw, ExternalLink,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { PageHeader } from '@/components/shared/page-header'
import { api } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface OrgIntegration {
  id: string
  provider: string
  name: string
  is_active: boolean
  has_config: boolean
  events: string[]
  last_status: string | null
  last_error: string | null
  last_used_at: string | null
  created_at: string
}

interface ConfigField {
  key: string
  label: string
  placeholder?: string
  type?: 'text' | 'password' | 'url'
  note?: string
}

interface ProviderDef {
  provider: string
  label: string
  description: string
  icon: typeof Bell
  configFields: ConfigField[]
  hasEvents: boolean
  tab: 'notifications' | 'siem' | 'ticketing' | 'devsecops' | 'threat-intel'
}

// ── Provider definitions ──────────────────────────────────────────────────────

const PROVIDERS: ProviderDef[] = [
  // Notifications
  {
    provider: 'slack',
    label: 'Slack',
    description: 'Send finding alerts and scan notifications to a Slack channel.',
    icon: Bell,
    configFields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...', type: 'url' },
    ],
    hasEvents: true,
    tab: 'notifications',
  },
  {
    provider: 'teams',
    label: 'Microsoft Teams',
    description: 'Post scan alerts to a Teams channel via Incoming Webhook.',
    icon: Bell,
    configFields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...', type: 'url' },
    ],
    hasEvents: true,
    tab: 'notifications',
  },
  {
    provider: 'pagerduty',
    label: 'PagerDuty',
    description: 'Page on-call engineers when critical findings are detected.',
    icon: Zap,
    configFields: [
      { key: 'routing_key', label: 'Routing / Integration Key', placeholder: '••••••••', type: 'password' },
    ],
    hasEvents: true,
    tab: 'notifications',
  },
  // SIEM
  {
    provider: 'splunk',
    label: 'Splunk',
    description: 'Send events to Splunk via HTTP Event Collector (HEC).',
    icon: Database,
    configFields: [
      { key: 'hec_url', label: 'HEC URL', placeholder: 'https://splunk.internal:8088/services/collector', type: 'url' },
      { key: 'hec_token', label: 'HEC Token', placeholder: '••••••••', type: 'password' },
      { key: 'index', label: 'Index', placeholder: 'main' },
      { key: 'source', label: 'Source (optional)', placeholder: 'exposurescopex' },
    ],
    hasEvents: true,
    tab: 'siem',
  },
  {
    provider: 'elastic',
    label: 'Elastic / OpenSearch',
    description: 'Forward findings to Elasticsearch or OpenSearch via API.',
    icon: Database,
    configFields: [
      { key: 'url', label: 'Cluster URL', placeholder: 'https://elastic.internal:9200', type: 'url' },
      { key: 'api_key', label: 'API Key', placeholder: '••••••••', type: 'password' },
      { key: 'index', label: 'Index name', placeholder: 'exposurescopex-findings' },
    ],
    hasEvents: true,
    tab: 'siem',
  },
  // Ticketing
  {
    provider: 'jira',
    label: 'Jira Cloud',
    description: 'Auto-create Jira issues for HIGH and CRITICAL findings.',
    icon: Bug,
    configFields: [
      { key: 'base_url', label: 'Jira Base URL', placeholder: 'https://yourorg.atlassian.net', type: 'url' },
      { key: 'email', label: 'Account Email', placeholder: 'you@yourorg.com' },
      { key: 'api_token', label: 'API Token', placeholder: '••••••••', type: 'password' },
      { key: 'project_key', label: 'Project Key', placeholder: 'SEC' },
      { key: 'issue_type', label: 'Issue Type', placeholder: 'Bug' },
    ],
    hasEvents: true,
    tab: 'ticketing',
  },
  // DevSecOps
  {
    provider: 'github_sarif',
    label: 'GitHub Advanced Security',
    description: 'Upload SARIF results to GitHub Code Scanning for pull-request annotations.',
    icon: GitBranch,
    configFields: [
      { key: 'token', label: 'Personal Access Token', placeholder: 'ghp_••••••••', type: 'password' },
      { key: 'owner', label: 'Owner (user or org)', placeholder: 'myorg' },
      { key: 'repo', label: 'Repository', placeholder: 'my-repo' },
      { key: 'ref', label: 'Branch / Ref', placeholder: 'refs/heads/main' },
    ],
    hasEvents: true,
    tab: 'devsecops',
  },
  {
    provider: 'gitlab_sarif',
    label: 'GitLab Security',
    description: 'Push SAST/DAST SARIF reports to GitLab Security Dashboard.',
    icon: GitBranch,
    configFields: [
      { key: 'token', label: 'Project Access Token', placeholder: 'glpat-••••••••', type: 'password' },
      { key: 'project_id', label: 'Project ID', placeholder: '12345678' },
      { key: 'base_url', label: 'GitLab URL (self-hosted or leave blank for gitlab.com)', placeholder: 'https://gitlab.com', type: 'url' },
    ],
    hasEvents: true,
    tab: 'devsecops',
  },
  // Threat Intel
  {
    provider: 'greynoise',
    label: 'GreyNoise',
    description: 'Enrich IP addresses in findings with GreyNoise noise and riot data.',
    icon: Shield,
    configFields: [
      {
        key: 'api_key',
        label: 'API Key',
        placeholder: 'gn-••••••••',
        type: 'password',
        note: 'Leave blank to use the free community tier (limited to 1 req/s).',
      },
    ],
    hasEvents: false,
    tab: 'threat-intel',
  },
]

const EVENT_OPTIONS = [
  { value: 'scan.completed', label: 'Scan completed' },
  { value: 'scan.failed', label: 'Scan failed' },
  { value: 'finding.critical', label: 'Critical finding' },
  { value: 'finding.high', label: 'High finding' },
  { value: 'assessment.completed', label: 'Assessment completed' },
  { value: 'asset.new', label: 'New asset discovered' },
  { value: 'asset.removed', label: 'Asset removed' },
  { value: 'asset.changed', label: 'Asset changed' },
  { value: 'service.new', label: 'New service discovered' },
  { value: 'certificate.new', label: 'New certificate' },
  { value: 'api.new', label: 'New API discovered' },
  { value: 'api.shadowed', label: 'Shadow API discovered' },
  { value: 'cloud.exposure', label: 'Cloud exposure' },
  { value: 'identity.changed', label: 'Identity exposure changed' },
  { value: 'secret.discovered', label: 'Secret discovered' },
  { value: 'cve.exploitable', label: 'Exploitable CVE' },
  { value: 'kev.exposed', label: 'Known exploited vulnerability' },
  { value: 'attackpath.created', label: 'Attack path created' },
  { value: 'attackpath.expanded', label: 'Attack path expanded' },
  { value: 'mcp.server.new', label: 'New MCP server' },
  { value: 'mcp.tool.changed', label: 'MCP tool changed' },
  { value: 'mcp.authorization.changed', label: 'MCP authorization changed' },
  { value: 'agent.new', label: 'New agent discovered' },
  { value: 'ai.endpoint.new', label: 'New AI endpoint' },
]

const TABS = [
  { id: 'notifications', label: 'Notifications' },
  { id: 'siem', label: 'SIEM' },
  { id: 'ticketing', label: 'Ticketing' },
  { id: 'devsecops', label: 'DevSecOps' },
  { id: 'cloud-sources', label: 'Cloud Sources' },
  { id: 'threat-intel', label: 'Threat Intel' },
] as const

type TabId = typeof TABS[number]['id']

// ── Helpers ───────────────────────────────────────────────────────────────────

function StatusBadge({ integration }: { integration: OrgIntegration | null }) {
  if (!integration) {
    return <Badge variant="secondary" className="text-[11px] px-2 py-0.5">Not configured</Badge>
  }
  if (!integration.is_active) {
    return <Badge variant="secondary" className="text-[11px] px-2 py-0.5">Disabled</Badge>
  }
  if (integration.last_status === 'ok') {
    return (
      <Badge className="text-[11px] px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
        <CheckCircle2 className="h-3 w-3 mr-1" /> Connected
      </Badge>
    )
  }
  if (integration.last_status === 'error') {
    return (
      <Badge className="text-[11px] px-2 py-0.5 bg-red-500/20 text-red-400 border-red-500/30">
        <XCircle className="h-3 w-3 mr-1" /> Error
      </Badge>
    )
  }
  if (integration.has_config) {
    return (
      <Badge className="text-[11px] px-2 py-0.5 bg-amber-500/20 text-amber-400 border-amber-500/30">
        <AlertCircle className="h-3 w-3 mr-1" /> Configured
      </Badge>
    )
  }
  return <Badge variant="secondary" className="text-[11px] px-2 py-0.5">Not configured</Badge>
}

// ── Integration card ──────────────────────────────────────────────────────────

function IntegrationCard({
  def,
  existing,
  onSaved,
  onDeleted,
}: {
  def: ProviderDef
  existing: OrgIntegration | null
  onSaved: () => void
  onDeleted: () => void
}) {
  const Icon = def.icon

  const [expanded, setExpanded] = useState(false)
  const [configValues, setConfigValues] = useState<Record<string, string>>({})
  const [selectedEvents, setSelectedEvents] = useState<string[]>(existing?.events ?? [])
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const { toast } = useToast()

  const toggleExpand = () => {
    setExpanded(e => !e)
    setTestResult(null)
    setSaveError(null)
  }

  const toggleEvent = (ev: string) => {
    setSelectedEvents(prev =>
      prev.includes(ev) ? prev.filter(e => e !== ev) : [...prev, ev]
    )
  }

  const handleSave = async () => {
    setSaving(true)
    setSaveError(null)
    try {
      const config: Record<string, string> = {}
      for (const field of def.configFields) {
        if (configValues[field.key]) config[field.key] = configValues[field.key]
      }
      const body = {
        provider: def.provider,
        name: def.label,
        config,
        events: def.hasEvents ? selectedEvents : [],
        is_active: true,
      }
      if (existing) {
        await api.put(`/api/v1/integrations/${existing.id}`, body)
      } else {
        await api.post('/api/v1/integrations', body)
      }
      setExpanded(false)
      onSaved()
    } catch (err: any) {
      setSaveError(err?.response?.data?.detail ?? 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    if (!existing) return
    setTesting(true)
    setTestResult(null)
    try {
      const res = await api.post<{ ok: boolean; message: string }>(
        `/api/v1/integrations/${existing.id}/test`
      )
      setTestResult(res.data)
    } catch (err: any) {
      setTestResult({ ok: false, message: err?.response?.data?.detail ?? 'Test failed' })
    } finally {
      setTesting(false)
    }
  }

  const handleDelete = async () => {
    if (!existing) return
    if (!confirm(`Disconnect ${def.label}? This cannot be undone.`)) return
    setDeleting(true)
    try {
      await api.delete(`/api/v1/integrations/${existing.id}`)
      onDeleted()
      toast({
        title: 'Integration disconnected',
        description: `${def.label} was removed successfully.`,
      })
    } catch (err: any) {
      toast({
        title: 'Could not disconnect integration',
        description: err?.response?.data?.detail ?? 'Delete failed',
        variant: 'destructive',
      })
    } finally {
      setDeleting(false)
    }
  }

  return (
    <Card className="border-border/50 bg-card/60 backdrop-blur-sm">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
              <Icon className="h-4 w-4 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <CardTitle className="text-sm font-semibold">{def.label}</CardTitle>
                <StatusBadge integration={existing} />
              </div>
              <CardDescription className="text-xs mt-0.5">{def.description}</CardDescription>
            </div>
          </div>
          <button
            onClick={toggleExpand}
            className="text-muted-foreground hover:text-foreground transition-colors shrink-0 mt-0.5"
            aria-label={expanded ? 'Collapse' : 'Configure'}
          >
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>
      </CardHeader>

      {/* Inline expanded form */}
      {expanded && (
        <CardContent className="pt-0 space-y-4 border-t border-border/40 mt-2 pt-4">
          {/* Config fields */}
          <div className="space-y-3">
            {def.configFields.map(field => (
              <div key={field.key} className="space-y-1.5">
                <Label htmlFor={`${def.provider}-${field.key}`} className="text-xs">
                  {field.label}
                </Label>
                <Input
                  id={`${def.provider}-${field.key}`}
                  type={field.type === 'password' ? 'password' : 'text'}
                  placeholder={field.placeholder}
                  value={configValues[field.key] ?? ''}
                  onChange={e =>
                    setConfigValues(prev => ({ ...prev, [field.key]: e.target.value }))
                  }
                  className="h-8 text-xs bg-background/60 font-mono"
                  autoComplete="off"
                />
                {field.note && (
                  <p className="text-[11px] text-muted-foreground">{field.note}</p>
                )}
              </div>
            ))}
          </div>

          {/* Events */}
          {def.hasEvents && (
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground uppercase tracking-wide">
                Trigger on events
              </Label>
              <div className="space-y-1.5">
                {EVENT_OPTIONS.map(ev => (
                  <label
                    key={ev.value}
                    className="flex items-center gap-2 cursor-pointer select-none"
                  >
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 rounded border-border accent-primary"
                      checked={selectedEvents.includes(ev.value)}
                      onChange={() => toggleEvent(ev.value)}
                    />
                    <span className="text-xs">{ev.label}</span>
                    <code className="ml-auto text-[10px] text-muted-foreground">
                      {ev.value}
                    </code>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Test result */}
          {testResult && (
            <div
              className={`rounded-md px-3 py-2 text-xs flex items-start gap-2 ${
                testResult.ok
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'bg-red-500/10 text-red-400 border border-red-500/20'
              }`}
            >
              {testResult.ok ? (
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              ) : (
                <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              )}
              <span>{testResult.message}</span>
            </div>
          )}

          {/* Save error */}
          {saveError && (
            <div className="rounded-md px-3 py-2 text-xs flex items-start gap-2 bg-red-500/10 text-red-400 border border-red-500/20">
              <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              <span>{saveError}</span>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-2 pt-1">
            <Button
              size="sm"
              className="h-7 text-xs px-3"
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? <Loader2 className="h-3 w-3 animate-spin mr-1.5" /> : null}
              {existing ? 'Update' : 'Save'}
            </Button>

            {existing && (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs px-3"
                onClick={handleTest}
                disabled={testing}
              >
                {testing ? <Loader2 className="h-3 w-3 animate-spin mr-1.5" /> : null}
                Test connection
              </Button>
            )}

            {existing && (
              <Button
                size="sm"
                variant="ghost"
                className="h-7 text-xs px-3 ml-auto text-red-400 hover:text-red-300 hover:bg-red-500/10"
                onClick={handleDelete}
                disabled={deleting}
              >
                {deleting ? <Loader2 className="h-3 w-3 animate-spin mr-1.5" /> : null}
                Disconnect
              </Button>
            )}
          </div>
        </CardContent>
      )}
    </Card>
  )
}

// ── Threat Intel status cards (read-only) ─────────────────────────────────────

function ThreatIntelStatusCard({
  title,
  icon: Icon,
  description,
  action,
}: {
  title: string
  icon: typeof Shield
  description: string
  action?: React.ReactNode
}) {
  return (
    <Card className="border-border/50 bg-card/60">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
              <Icon className="h-4 w-4 text-primary" />
            </div>
            <div>
              <CardTitle className="text-sm font-semibold">{title}</CardTitle>
              <CardDescription className="text-xs mt-0.5">{description}</CardDescription>
            </div>
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </div>
      </CardHeader>
    </Card>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function IntegrationsPage() {
  const [tab, setTab] = useState<TabId>('notifications')
  const [integrations, setIntegrations] = useState<OrgIntegration[]>([])
  const [loading, setLoading] = useState(true)
  const [nvdSyncing, setNvdSyncing] = useState(false)
  const [nvdResult, setNvdResult] = useState<string | null>(null)

  const fetchIntegrations = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get<OrgIntegration[]>('/api/v1/integrations')
      setIntegrations(res.data)
    } catch {
      setIntegrations([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchIntegrations()
  }, [fetchIntegrations])

  const handleNvdSync = async () => {
    setNvdSyncing(true)
    setNvdResult(null)
    try {
      const res = await api.post<{
        cves_fetched: number
        asset_matches: number
        status: string
        message: string
      }>('/api/v1/integrations/nvd-sync')
      setNvdResult(
        `${res.data.cves_fetched} CVEs ingested, ${res.data.asset_matches} asset matches`
      )
    } catch (err: any) {
      setNvdResult('Sync failed: ' + (err?.response?.data?.detail ?? 'unknown error'))
    } finally {
      setNvdSyncing(false)
    }
  }

  // Map providers for current tab
  const tabProviders = PROVIDERS.filter(p => p.tab === tab)

  const findExisting = (provider: string) =>
    integrations.find(i => i.provider === provider) ?? null

  const greynoiseDef = PROVIDERS.find(p => p.provider === 'greynoise')!
  const greynoiseExisting = findExisting('greynoise')

  return (
    <div className="space-y-6">
      <PageHeader
        title="Integrations"
        description="Connect ExposureScopeX to notification channels, SIEM platforms, ticketing systems, and threat intel sources"
      />

      {/* Tab nav */}
      <div className="flex border-b border-border gap-0.5">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap ${
              tab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Cloud Sources tab — link to ASM */}
      {tab === 'cloud-sources' && (
        <div className="space-y-4">
          <Card className="border-border/50 bg-card/60 backdrop-blur-sm">
            <CardHeader>
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <Cloud className="h-4 w-4 text-primary" />
                </div>
                <div className="flex-1">
                  <CardTitle className="text-sm font-semibold">
                    Cloud Provider Connections
                  </CardTitle>
                  <CardDescription className="text-xs mt-0.5">
                    AWS, GCP, Azure, and on-premises cloud source configurations are managed in the
                    Attack Surface Management module.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <Button
                variant="outline"
                size="sm"
                className="h-8 text-xs gap-1.5"
                onClick={() => (window.location.href = '/asm')}
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Manage cloud sources in ASM
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Threat Intel tab */}
      {tab === 'threat-intel' && (
        <div className="space-y-4">
          {/* MITRE ATT&CK — automatic, no config */}
          <ThreatIntelStatusCard
            title="MITRE ATT&CK Tagging"
            icon={Shield}
            description="Automatically applied to all findings during scan using a static pattern library. No configuration required."
            action={
              <Badge className="text-[11px] px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                <CheckCircle2 className="h-3 w-3 mr-1" /> Always on
              </Badge>
            }
          />

          {/* NVD CVE Feed */}
          <Card className="border-border/50 bg-card/60 backdrop-blur-sm">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Database className="h-4 w-4 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-sm font-semibold">NVD CVE Feed</CardTitle>
                    <CardDescription className="text-xs mt-0.5">
                      Ingests daily CVE publications from the NIST NVD 2.0 API and matches them
                      against technologies tracked in your asset inventory. Runs automatically
                      every 24 hours via scheduled task.
                    </CardDescription>
                  </div>
                </div>
                <Badge className="shrink-0 text-[11px] px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                  <CheckCircle2 className="h-3 w-3 mr-1" /> Scheduled
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="pt-0 border-t border-border/40 mt-2 pt-4 space-y-3">
              <div className="flex items-center gap-3">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs px-3 gap-1.5"
                  onClick={handleNvdSync}
                  disabled={nvdSyncing}
                >
                  {nvdSyncing ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <RefreshCw className="h-3 w-3" />
                  )}
                  Sync now
                </Button>
                {nvdResult && (
                  <span className="text-xs text-muted-foreground">{nvdResult}</span>
                )}
              </div>
            </CardContent>
          </Card>

          {/* GreyNoise — uses the same IntegrationCard */}
          <IntegrationCard
            def={greynoiseDef}
            existing={greynoiseExisting}
            onSaved={fetchIntegrations}
            onDeleted={fetchIntegrations}
          />
        </div>
      )}

      {/* All other tabs — provider cards */}
      {tab !== 'cloud-sources' && tab !== 'threat-intel' && (
        <div className="space-y-4">
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-8 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading integrations…
            </div>
          ) : tabProviders.length === 0 ? (
            <div className="text-center py-8 text-sm text-muted-foreground">
              No integrations available for this category.
            </div>
          ) : (
            tabProviders.map(def => (
              <IntegrationCard
                key={def.provider}
                def={def}
                existing={findExisting(def.provider)}
                onSaved={fetchIntegrations}
                onDeleted={fetchIntegrations}
              />
            ))
          )}
        </div>
      )}
    </div>
  )
}
