'use client'

import React, { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Crosshair, Loader2, Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useToast } from '@/components/ui/use-toast'
import { PageHeader } from '@/components/shared/page-header'
import { SCAN_MODES, SCAN_PHASES } from '@/lib/constants'
import { createAssessment, getSavedScanProfiles, getScanProfiles, previewAssessment, saveScanProfile } from '@/lib/api'
import type { Assessment, ExecutionPreview, ImportedAssessmentTarget, SavedScanProfile, ScanProfile } from '@/lib/types'
import { cn } from '@/lib/utils'

type AssessmentTargetType = Assessment['target_type']
const IMPORT_DRAFT_STORAGE_KEY = 'assessment-import-draft'

function detectTargetType(target: string): AssessmentTargetType | 'unknown' {
  if (!target) return 'unknown'
  if (/^https?:\/\/.*\.apk(?:\?|$)/i.test(target)) return 'android'
  if (/^https?:\/\/.*\.ipa(?:\?|$)/i.test(target)) return 'ios'
  if (/^https?:\/\/.*(?:k8s|kubernetes).*(?:\.ya?ml)(?:\?|$)/i.test(target)) return 'kubernetes'
  if (/^https?:\/\/.*(?:openapi|swagger)(?:[./?]|$)/i.test(target)) return 'api'
  if (/^https?:\/\/.+\/mcp(?:\/|$)/i.test(target)) return 'mcp'
  if (/^https?:\/\//.test(target)) return 'url'
  if (/^(?:AS)?\d{1,10}$/i.test(target)) return 'asn'
  if (/^(?:(?:https?:\/\/)?(?:www\.)?)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?(?:\.git)?$/i.test(target)) return 'repository'
  if (
    /^(?:(?:[a-z0-9.-]+(?::\d+)?)\/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[\w][\w.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/i.test(target) &&
    (target.includes('@') || target.includes(':') || target.split('/').length > 1)
  ) return 'image'
  if (/^(?:\d{12}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[a-z][a-z0-9-]{4,61}[a-z0-9]|(?:aws|azure|gcp):.+)$/i.test(target)) return 'cloud_account'
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(target)) return 'cidr'
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return 'ip'
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}/.test(target)) return 'domain'
  return 'unknown'
}

function parseManualTargets(input: string): ImportedAssessmentTarget[] {
  const values = input
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)

  const seen = new Set<string>()
  const parsed: ImportedAssessmentTarget[] = []
  for (const value of values) {
    const targetType = detectTargetType(value)
    const normalizedType = targetType === 'unknown' ? 'domain' : targetType
    const key = `${normalizedType}:${value.toLowerCase()}`
    if (seen.has(key)) continue
    seen.add(key)
    parsed.push({
      name: value,
      target: value,
      target_type: normalizedType,
    })
  }
  return parsed
}

function splitMultiValueInput(input: string): string[] {
  return input
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function buildAssessmentTargetBatch(
  primaryTarget: string,
  importedTargets: ImportedAssessmentTarget[],
  manualTargets: ImportedAssessmentTarget[],
  primaryTypeOverride?: AssessmentTargetType
): ImportedAssessmentTarget[] {
  const batch: ImportedAssessmentTarget[] = []
  const seen = new Set<string>()

  const addTarget = (item: ImportedAssessmentTarget | null) => {
    if (!item?.target) return
    const key = `${item.target_type}:${item.target.toLowerCase()}`
    if (seen.has(key)) return
    seen.add(key)
    batch.push(item)
  }

  if (primaryTarget.trim()) {
    const primaryType = primaryTypeOverride || detectTargetType(primaryTarget)
    addTarget({
      name: primaryTarget.trim(),
      target: primaryTarget.trim(),
      target_type: primaryType === 'unknown' ? 'domain' : primaryType,
    })
  }

  for (const item of importedTargets) addTarget(item)
  for (const item of manualTargets) addTarget(item)
  return batch
}

export default function NewAssessmentPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [target, setTarget] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [scanMode, setScanMode] = useState('medium')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scanProfiles, setScanProfiles] = useState<ScanProfile[]>([])
  const [savedProfiles, setSavedProfiles] = useState<SavedScanProfile[]>([])
  const [profileName, setProfileName] = useState('')
  const [preview, setPreview] = useState<ExecutionPreview | null>(null)
  const [importedTargets, setImportedTargets] = useState<ImportedAssessmentTarget[]>([])
  const [manualTargets, setManualTargets] = useState<ImportedAssessmentTarget[]>([])
  const [draftTargetsInput, setDraftTargetsInput] = useState('')
  const [autoStart, setAutoStart] = useState(true)
  const [requestedScansInput, setRequestedScansInput] = useState('')
  const [requestedUtilitiesInput, setRequestedUtilitiesInput] = useState('')
  const [nucleiTagsInput, setNucleiTagsInput] = useState('')
  const [targetTypeOverride, setTargetTypeOverride] = useState<AssessmentTargetType | 'auto'>('auto')

  const [phases, setPhases] = useState<Record<string, boolean>>({
    enum: true,
    scan: true,
    cloud: true,
    report: true,
  })

  const [flags, setFlags] = useState({
    passive_only: false,
    stealth: false,
    screenshots: false,
    cve: false,
    crawl: false,
    agent: false,
    no_osint: false,
    diff: false,
    baseline: false,
    allow_active_validation: false,
  })

  const detectedTargetType = detectTargetType(target)
  const targetType = targetTypeOverride === 'auto' ? detectedTargetType : targetTypeOverride
  const assessmentTargets = buildAssessmentTargetBatch(
    target,
    importedTargets,
    manualTargets,
    targetType === 'unknown' ? undefined : targetType
  )
  const isImportedBatch = importedTargets.length > 0
  const isBatchAssessment = assessmentTargets.length > 1
  const effectiveTargetType =
    isBatchAssessment
      ? 'file'
      : targetType === 'unknown'
        ? 'domain'
        : targetType

  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    if (params.get('import') !== '1') return

    const rawDraft = sessionStorage.getItem(IMPORT_DRAFT_STORAGE_KEY)
    if (!rawDraft) return

    try {
      const draft = JSON.parse(rawDraft) as {
        importedTargets?: ImportedAssessmentTarget[]
        suggestedName?: string
        suggestedDescription?: string
      }
      const draftTargets = draft.importedTargets || []
      if (draftTargets.length === 0) return
      setImportedTargets(draftTargets)
      setName((current) => current || draft.suggestedName || 'Imported Assessment')
      setDescription((current) => current || draft.suggestedDescription || '')
      setTarget((current) => current || draftTargets[0]?.target || '')
    } catch {
      sessionStorage.removeItem(IMPORT_DRAFT_STORAGE_KEY)
    }
  }, [])

  useEffect(() => {
    let cancelled = false

    async function loadProfiles() {
      try {
        const profiles = await getScanProfiles(effectiveTargetType)
        if (!cancelled) {
          setScanProfiles(profiles)
        }
      } catch {
        if (!cancelled) {
          setScanProfiles([])
        }
      }
    }

    void loadProfiles()
    getSavedScanProfiles(effectiveTargetType).then(setSavedProfiles).catch(() => setSavedProfiles([]))
    return () => {
      cancelled = true
    }
  }, [effectiveTargetType])

  useEffect(() => {
    const profile = scanProfiles.find((item) => item.mode === scanMode)
    if (!profile) return
    setPhases(profile.phases)
    setFlags((current) => ({ ...current, ...profile.flags }))
  }, [scanMode, scanProfiles])

  const togglePhase = useCallback((phaseId: string) => {
    setPhases((prev) => ({ ...prev, [phaseId]: !prev[phaseId] }))
  }, [])

  const applySavedProfile = (id: string) => {
    const profile = savedProfiles.find((item) => item.id === id)
    if (!profile) return
    const config = profile.configuration as { phases?: Record<string, boolean>; flags?: typeof flags; requested_scans?: string[]; requested_utilities?: string[]; nuclei_tags?: string[] }
    setScanMode(profile.scan_mode); if (config.phases) setPhases(config.phases); if (config.flags) setFlags(config.flags)
    setRequestedScansInput((config.requested_scans || []).join(', ')); setRequestedUtilitiesInput((config.requested_utilities || []).join(', ')); setNucleiTagsInput((config.nuclei_tags || []).join(', '))
  }

  const persistProfile = async () => {
    if (!profileName.trim()) return
    const saved = await saveScanProfile({ name: profileName.trim(), description: description || undefined, target_type: effectiveTargetType,
      scan_mode: scanMode as Assessment['scan_mode'], configuration: { phases, flags, requested_scans: splitMultiValueInput(requestedScansInput), requested_utilities: splitMultiValueInput(requestedUtilitiesInput), nuclei_tags: splitMultiValueInput(nucleiTagsInput) } })
    setSavedProfiles((current) => [...current.filter((item) => item.name !== saved.name), saved]); setProfileName('')
    toast({ title: 'Scan profile saved', description: `${saved.name} version ${saved.version}` })
  }

  const handleAddTargets = useCallback(() => {
    const parsedTargets = parseManualTargets(draftTargetsInput)
    if (parsedTargets.length === 0) return
    setManualTargets((current) => buildAssessmentTargetBatch('', current, parsedTargets))
    setDraftTargetsInput('')
  }, [draftTargetsInput])

  const handleRemoveTarget = useCallback((item: ImportedAssessmentTarget) => {
    const filteredImported = importedTargets.filter(
      (current) => !(current.target === item.target && current.target_type === item.target_type)
    )
    const filteredManual = manualTargets.filter(
      (current) => !(current.target === item.target && current.target_type === item.target_type)
    )

    setImportedTargets(filteredImported)
    setManualTargets(filteredManual)

    if (target.trim() === item.target.trim()) {
      const remaining = buildAssessmentTargetBatch('', filteredImported, filteredManual)
      setTarget(remaining[0]?.target || '')
    }
  }, [importedTargets, manualTargets, target])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const assessment = await createAssessment({
        name: name.trim(),
        description: description.trim() || undefined,
        target: target.trim(),
        target_type: effectiveTargetType,
        scan_mode: scanMode as 'light' | 'medium' | 'aggressive',
        phases,
        flags,
        requested_scans: splitMultiValueInput(requestedScansInput),
        requested_utilities: splitMultiValueInput(requestedUtilitiesInput),
        nuclei_tags: splitMultiValueInput(nucleiTagsInput),
        imported_targets: assessmentTargets,
        auto_start: autoStart,
      })
      if (typeof window !== 'undefined') {
        sessionStorage.removeItem(IMPORT_DRAFT_STORAGE_KEY)
      }
      toast({
        title: 'Assessment started',
        description: `${assessment.name} was created and queued for scanning.`,
      })

      router.push('/assessments')
    } catch (err) {
      const message =
        typeof err === 'object' &&
        err !== null &&
        'response' in err &&
        typeof (err as { response?: { data?: { detail?: string } } }).response?.data?.detail === 'string'
          ? (err as { response?: { data?: { detail?: string } } }).response!.data!.detail!
          : 'Unable to create the assessment. Please verify the API connection and try again.'

      setError(message)
      toast({
        title: 'Assessment creation failed',
        description: message,
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }

  const loadPreview = async () => {
    setLoading(true); setError(null)
    try { setPreview(await previewAssessment({ name: name.trim() || 'Preview', description: description || undefined, target: target.trim(), target_type: effectiveTargetType,
      scan_mode: scanMode as Assessment['scan_mode'], phases, flags, requested_scans: splitMultiValueInput(requestedScansInput), requested_utilities: splitMultiValueInput(requestedUtilitiesInput), nuclei_tags: splitMultiValueInput(nucleiTagsInput), imported_targets: assessmentTargets, auto_start: false })) }
    catch (error) { setError(error instanceof Error ? error.message : 'Execution preview failed') }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        title="New Assessment"
        description="Configure and launch a new security assessment"
      />

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-primary" />
              Target Configuration
            </CardTitle>
            <CardDescription>
              {isImportedBatch
                ? 'Review the imported targets and choose the primary focus for the assessment'
                : 'Define the target for your assessment'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Assessment Name</Label>
              <Input
                id="name"
                placeholder="e.g., Acme Corp Quarterly Scan"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="target">
                {isImportedBatch ? 'Primary Target / Focus (Optional)' : 'Target (Web/API, Network, Repo, Image, Kubernetes, Mobile, Cloud, or MCP)'}
              </Label>
              <Input
                id="target"
                placeholder={isImportedBatch ? 'Optional override for the imported batch focus' : 'e.g., example.com, openapi.json URL, public manifest.yaml/APK/IPA URL, image, cloud account, or MCP endpoint'}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required={!isImportedBatch}
              />
              {(target || (isImportedBatch && assessmentTargets[0]?.target)) && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Detected type:</span>
                  <Badge variant="outline" className="text-xs capitalize">{effectiveTargetType}</Badge>
                </div>
              )}
              {!isBatchAssessment && (
                <div className="space-y-2">
                  <Label htmlFor="target-type">Target Type</Label>
                  <select
                    id="target-type"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={targetTypeOverride}
                    onChange={(event) => setTargetTypeOverride(event.target.value as AssessmentTargetType | 'auto')}
                  >
                    <option value="auto">Auto detect</option>
                    <option value="domain">Domain</option>
                    <option value="url">Web URL</option>
                    <option value="api">API / OpenAPI</option>
                    <option value="ip">IP address</option>
                    <option value="cidr">CIDR range</option>
                    <option value="repository">Repository</option>
                    <option value="image">Container image</option>
                    <option value="kubernetes">Kubernetes manifest</option>
                    <option value="android">Android APK</option>
                    <option value="ios">iOS IPA</option>
                    <option value="cloud_account">Cloud account</option>
                    <option value="mcp">MCP endpoint</option>
                  </select>
                  <p className="text-xs text-muted-foreground">Override auto detection for ambiguous URLs and artifact names.</p>
                </div>
              )}
              {isImportedBatch ? (
                <p className="text-xs text-muted-foreground">
                  The imported assets already define the assessment scope. Leave this blank unless you want to pin a different headline target.
                </p>
              ) : null}

              {scanProfiles.find((profile) => profile.mode === scanMode)?.tool_plan?.length ? (
                <div className="rounded-lg border border-border/70 bg-muted/20 p-4">
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium">Planned tool execution</p>
                      <p className="text-xs text-muted-foreground">The selected profile resolves into this normalized tool plan.</p>
                    </div>
                    <Badge variant="outline">{scanProfiles.find((profile) => profile.mode === scanMode)?.tool_plan.length} tools</Badge>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {scanProfiles.find((profile) => profile.mode === scanMode)?.tool_plan.map((tool) => (
                      <Badge key={`${tool.tool_id}-${tool.role}`} variant={tool.required ? 'default' : 'secondary'}>
                        {tool.name}
                      </Badge>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
            {assessmentTargets.length > 1 || isImportedBatch ? (
              <div className="rounded-lg border border-border/70 bg-muted/30 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium">Imported Targets</p>
                    <p className="text-xs text-muted-foreground">
                      This assessment will keep one setup and attach all normalized targets inside it.
                    </p>
                  </div>
                  <Badge variant="secondary">{assessmentTargets.length} targets</Badge>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {assessmentTargets.slice(0, 12).map((item) => (
                    <Badge key={`${item.target_type}:${item.target}`} variant="outline" className="max-w-full gap-2 pr-1">
                      <span className="truncate">{item.target}</span>
                      <button
                        type="button"
                        aria-label={`Remove ${item.target}`}
                        className="rounded-sm p-0.5 transition hover:bg-muted"
                        onClick={() => handleRemoveTarget(item)}
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                  {assessmentTargets.length > 12 ? (
                    <Badge variant="outline">+{assessmentTargets.length - 12} more</Badge>
                  ) : null}
                </div>
              </div>
            ) : null}
            <div className="space-y-2">
              <Label htmlFor="additional-targets">Add More Assets / Targets</Label>
              <div className="flex gap-2">
                <Textarea
                  id="additional-targets"
                  placeholder="Paste more domains, IPs, CIDRs, or URLs. Use one per line, comma, or semicolon."
                  value={draftTargetsInput}
                  onChange={(e) => setDraftTargetsInput(e.target.value)}
                  rows={3}
                />
                <Button type="button" variant="outline" className="shrink-0 self-start" onClick={handleAddTargets}>
                  <Plus className="mr-2 h-4 w-4" />
                  Add
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                {isBatchAssessment
                  ? `This assessment will scan a batch of ${assessmentTargets.length} normalized targets.`
                  : 'Leave blank to run a single-target assessment.'}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                placeholder="Optional context for this assessment"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Advanced Tooling</CardTitle>
            <CardDescription>
              Add focused scan packs or utilities when you want more coverage without changing the whole profile.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="requested-scans">Requested Scan Packs</Label>
              <Input
                id="requested-scans"
                placeholder="e.g., web, api, nuclei, cloud"
                value={requestedScansInput}
                onChange={(e) => setRequestedScansInput(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Comma, semicolon, or newline separated. Useful for forcing web, API, nuclei, or cloud-specific passes.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="requested-utilities">Requested Utilities</Label>
              <Input
                id="requested-utilities"
                placeholder="e.g., ffuf, arjun, nikto, sqlmap, scoutsuite"
                value={requestedUtilitiesInput}
                onChange={(e) => setRequestedUtilitiesInput(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Add focused tools on top of the profile. Recommended examples: `ffuf`, `arjun`, `nikto`, `scoutsuite`.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="nuclei-tags">Extra Nuclei Tags</Label>
              <Input
                id="nuclei-tags"
                placeholder="e.g., workflows, panel, files, exposures"
                value={nucleiTagsInput}
                onChange={(e) => setNucleiTagsInput(e.target.value)}
              />
            </div>
            {(effectiveTargetType === 'domain' || effectiveTargetType === 'url' || effectiveTargetType === 'file') ? (
              <div className="flex items-center justify-between rounded-lg border border-border/70 bg-muted/20 p-4">
                <div>
                  <p className="text-sm font-medium">Authorized active validation</p>
                  <p className="text-xs text-muted-foreground">
                    Enables guarded tooling like `sqlmap`. Leave this off unless the scope explicitly allows active exploit validation.
                  </p>
                </div>
                <Switch
                  checked={Boolean(flags.allow_active_validation)}
                  onCheckedChange={(checked) => setFlags((current) => ({ ...current, allow_active_validation: checked }))}
                />
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card><CardHeader><CardTitle className="text-base">Team scan profiles</CardTitle><CardDescription>Reuse versioned execution settings without changing this assessment&apos;s target.</CardDescription></CardHeader><CardContent className="space-y-3"><select className="h-10 w-full rounded-md border bg-background px-3 text-sm" defaultValue="" onChange={(event) => applySavedProfile(event.target.value)}><option value="">Choose a saved profile</option>{savedProfiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · v{profile.version}</option>)}</select><div className="flex gap-2"><Input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder="Save current settings as..." /><Button type="button" variant="outline" disabled={!profileName.trim()} onClick={() => void persistProfile()}>Save profile</Button></div></CardContent></Card>

        {/* Scan Mode */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scan Mode</CardTitle>
            <CardDescription>Select the intensity of the scan</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {(scanProfiles.length > 0 ? scanProfiles : SCAN_MODES).map((mode) => {
                const value = 'mode' in mode ? mode.mode : mode.value
                const label = 'mode' in mode ? mode.label : mode.label
                const description = 'mode' in mode ? mode.description : mode.description
                const utilities = 'utilities' in mode ? mode.utilities : []

                return (
                <button
                  key={value}
                  type="button"
                  onClick={() => setScanMode(value)}
                  className={cn(
                    'rounded-lg border p-4 text-left transition-all',
                    scanMode === value
                      ? 'border-primary bg-primary/5 ring-1 ring-primary'
                      : 'border-border hover:border-primary/30'
                  )}
                >
                  <p className="text-sm font-medium">{label}</p>
                  <p className="text-xs text-muted-foreground mt-1">{description}</p>
                  {utilities.length > 0 ? (
                    <p className="mt-2 text-[11px] text-primary/80">
                      {utilities.slice(0, 4).join(' • ')}
                    </p>
                  ) : null}
                </button>
                )
              })}
            </div>
            {scanProfiles.find((item) => item.mode === scanMode) ? (
              <div className="mt-4 rounded-lg border border-border/70 bg-muted/30 p-4">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <Badge variant="secondary">{scanProfiles.find((item) => item.mode === scanMode)?.scan_strategy || 'active'}</Badge>
                  <span className="text-muted-foreground">Pipeline follows the normalized attack-surface workflow for this seed type.</span>
                </div>
                <p className="mt-3 text-xs font-medium text-muted-foreground">Pipeline</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(scanProfiles.find((item) => item.mode === scanMode)?.pipeline || []).map((step) => (
                    <Badge key={step} variant="outline" className="text-[10px]">{step.replace(/_/g, ' ')}</Badge>
                  ))}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>

        {/* Phases */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scan Phases</CardTitle>
            <CardDescription>Select which phases to include in the assessment</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {SCAN_PHASES.filter((p) => ['enumeration', 'port_scan', 'cloud', 'exploit', 'vuln'].includes(p.id)).map((phase) => {
                const phaseIdMap: Record<string, string> = {
                  enumeration: 'enum',
                  port_scan: 'scan',
                  cloud: 'cloud',
                  exploit: 'exploit',
                  vuln: 'report',
                }
                const mappedId = phaseIdMap[phase.id] || phase.id

                return (
                <button
                  key={phase.id}
                  type="button"
                  onClick={() => togglePhase(mappedId)}
                  className={cn(
                    'rounded-md border p-3 text-left transition-all',
                    phases[mappedId]
                      ? 'border-primary/50 bg-primary/5'
                      : 'border-border opacity-60 hover:opacity-80'
                  )}
                >
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium">{phase.label}</p>
                    <div className={cn('h-3 w-3 rounded-full', phases[mappedId] ? 'bg-primary' : 'bg-muted')} />
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-1">{phase.description}</p>
                </button>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Flags */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Advanced Options</CardTitle>
            <CardDescription>Configure additional scan behaviors</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Start Immediately</p>
                <p className="text-xs text-muted-foreground">Queue the scan as soon as the assessment is created.</p>
              </div>
              <Switch
                checked={autoStart}
                onCheckedChange={setAutoStart}
              />
            </div>
            {[
              { key: 'passive_only', label: 'Passive Only', desc: 'Zero-packet recon only. No active scanning.' },
              { key: 'stealth', label: 'Stealth Mode', desc: 'Randomized delays between tools to evade WAF/IDS.' },
              { key: 'screenshots', label: 'Screenshots', desc: 'Capture visual snapshots of web targets.' },
              { key: 'cve', label: 'CVE Correlation', desc: 'Match tech fingerprints against NVD CVE database.' },
              { key: 'crawl', label: 'Deep Crawl', desc: 'Dedicated deep web crawler phase.' },
              { key: 'no_osint', label: 'Skip OSINT', desc: 'Skip OSINT API calls (Shodan, VirusTotal, etc.).' },
              { key: 'diff', label: 'Diff Mode', desc: 'Compare results against previous scan.' },
              { key: 'baseline', label: 'Baseline Filter', desc: 'Only report new findings (implies diff).' },
              { key: 'agent', label: 'AI Agent', desc: 'Autonomous AI-driven assessment (requires Anthropic API key).' },
            ].map((flag) => (
              <div key={flag.key} className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">{flag.label}</p>
                  <p className="text-xs text-muted-foreground">{flag.desc}</p>
                </div>
                <Switch
                  checked={flags[flag.key as keyof typeof flags]}
                  onCheckedChange={(checked) => setFlags({ ...flags, [flag.key]: checked })}
                />
              </div>
            ))}
          </CardContent>
        </Card>

        {preview && <Card className="border-primary/30"><CardHeader><CardTitle className="text-base">Execution preview</CardTitle><CardDescription>Resolved by the backend without creating a scan.</CardDescription></CardHeader><CardContent className="space-y-4"><div className="grid gap-3 sm:grid-cols-5"><div><p className="text-xs text-muted-foreground">Targets</p><p className="font-semibold">{preview.target_count}</p></div><div><p className="text-xs text-muted-foreground">Tools</p><p className="font-semibold">{preview.tool_plan.length}</p></div><div><p className="text-xs text-muted-foreground">Estimated</p><p className="font-semibold">{Math.ceil(preview.estimated_seconds / 60)} min</p></div><div><p className="text-xs text-muted-foreground">Queue</p><p className="font-mono text-xs">{String(preview.execution_policy.queue || 'default')}</p></div><div><p className="text-xs text-muted-foreground">Confidence</p><p className="font-semibold capitalize">{preview.confidence}</p></div></div><div className="grid gap-2 sm:grid-cols-2">{preview.tool_plan.map((tool) => <div key={`${tool.tool_id}-${tool.role}`} className="rounded-lg border p-3"><div className="flex items-center justify-between"><p className="text-sm font-medium">{tool.name}</p><Badge variant={tool.required ? 'default' : 'outline'}>{tool.safety_tier?.replaceAll('_', ' ') || 'planned'}</Badge></div><p className="mt-1 text-xs text-muted-foreground">{tool.outputs.join(', ')}</p>{tool.prerequisites?.length ? <p className="mt-2 text-xs text-amber-600">Requires: {tool.prerequisites.join(', ')}</p> : null}</div>)}</div><div><p className="text-xs font-medium">Safety controls</p><div className="mt-2 flex flex-wrap gap-1.5">{preview.safety_controls.map((item) => <Badge key={item} variant="secondary">{item}</Badge>)}</div></div>{preview.exclusions.length ? <p className="text-xs text-muted-foreground">Excluded stages: {preview.exclusions.join(', ')}</p> : null}{preview.warnings.map((warning) => <p key={warning} className="text-xs text-amber-600">{warning}</p>)}</CardContent></Card>}

        {/* Submit */}
        <div className="flex justify-end gap-3">
          {error ? <p className="mr-auto text-sm text-destructive">{error}</p> : null}
          <Button type="button" variant="outline" onClick={() => router.push('/assessments')}>
            Cancel
          </Button>
          <Button type="button" variant="outline" disabled={loading || assessmentTargets.length === 0} onClick={() => void loadPreview()}>Preview execution</Button>
          <Button type="submit" disabled={loading || !name || assessmentTargets.length === 0}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Creating...
              </>
            ) : (
              'Start Assessment'
            )}
          </Button>
        </div>
      </form>
    </div>
  )
}
