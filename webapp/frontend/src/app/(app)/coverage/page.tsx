'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertCircle, CheckCircle2, FlaskConical, Layers3, PlugZap, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PageHeader } from '@/components/shared/page-header'
import { getCapabilityCatalog, getToolCatalog } from '@/lib/api'
import type { CapabilityCatalog, OpenSourceToolCatalog, PlatformCapability } from '@/lib/types'

const statusStyles: Record<PlatformCapability['status'], string> = {
  operational: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300',
  conditional: 'border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-300',
  partial: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-300',
  integration_required: 'border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-300',
  research: 'border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-300',
}

const statusIcons = {
  operational: CheckCircle2,
  conditional: ShieldCheck,
  partial: AlertCircle,
  integration_required: PlugZap,
  research: FlaskConical,
}

export default function CoveragePage() {
  const [catalog, setCatalog] = useState<CapabilityCatalog | null>(null)
  const [toolCatalog, setToolCatalog] = useState<OpenSourceToolCatalog | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getCapabilityCatalog().then(setCatalog).catch((reason) => {
      setError(reason?.response?.data?.detail || 'Could not load the platform capability registry.')
    })
    getToolCatalog().then(setToolCatalog).catch(() => {
      // Capability coverage remains useful even if tool inventory fails to load.
    })
  }, [])

  const bundledCount = useMemo(
    () => toolCatalog?.scanners.filter((scanner) => scanner.bundled).length || 0,
    [toolCatalog]
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Coverage"
        description="Executable coverage, bundled engines, optional adapters, and prerequisites mapped to the 2026 ASM and red-team blueprint."
      />

      {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">{error}</div>}

      {catalog && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            {Object.entries(catalog.counts).map(([status, count]) => (
              <Card key={status}>
                <CardContent className="p-4">
                  <div className="text-2xl font-semibold">{count}</div>
                  <div className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">{status.replaceAll('_', ' ')}</div>
                </CardContent>
              </Card>
            ))}
          </div>

          {toolCatalog && (
            <>
              <div className="grid gap-3 sm:grid-cols-3">
                <Card>
                  <CardContent className="p-4">
                    <div className="text-2xl font-semibold">{toolCatalog.counts.total}</div>
                    <div className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">Curated engines</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <div className="text-2xl font-semibold">{bundledCount}</div>
                    <div className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">Bundled modules</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <div className="text-2xl font-semibold">{Object.keys(toolCatalog.counts.by_category).length}</div>
                    <div className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">Engine families</div>
                  </CardContent>
                </Card>
              </div>

              <div className="rounded-xl border bg-muted/20 p-4">
                <div className="mb-3 flex items-center gap-2">
                  <Layers3 className="h-4 w-4 text-primary" />
                  <p className="text-sm font-medium">Open-source engine catalog</p>
                </div>
                <div className="grid gap-4 lg:grid-cols-2">
                  {toolCatalog.scanners.map((scanner) => (
                    <Card key={scanner.id} className="overflow-hidden border-border/70 bg-background/80">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between gap-3">
                          <CardTitle className="text-base">{scanner.name}</CardTitle>
                          <Badge variant="outline" className="capitalize">{scanner.status.replaceAll('_', ' ')}</Badge>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-3 text-sm">
                        <div className="flex flex-wrap gap-2">
                          <Badge variant="secondary">{scanner.category.replaceAll('_', ' ')}</Badge>
                          <Badge variant="secondary">{scanner.execution}</Badge>
                          <Badge variant="outline">{scanner.license}</Badge>
                        </div>
                        <p className="text-muted-foreground">{scanner.notes}</p>
                        <div className="text-xs text-muted-foreground">Targets: {scanner.target_types.join(' · ')}</div>
                        <div className="text-xs text-muted-foreground">Outputs: {scanner.outputs.join(' · ')}</div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            </>
          )}

          <div className="rounded-xl border bg-gradient-to-r from-emerald-500/5 via-background to-sky-500/5 p-4 text-sm text-muted-foreground">
            <div className="font-medium text-foreground">
              {catalog.document_coverage.mapped_sections}/{catalog.document_coverage.actionable_sections} actionable blueprint sections mapped
            </div>
            <div className="mt-1">
              “Operational” means a scan path executes and persists normalized output. Conditional, partial, and research items are never counted as executed automatically.
            </div>
            {catalog.document_coverage.unmapped_sections.length > 0 && (
              <div className="mt-2 text-destructive">Unmapped sections: {catalog.document_coverage.unmapped_sections.join(', ')}</div>
            )}
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            {catalog.capabilities.map((capability) => {
              const Icon = statusIcons[capability.status]
              return (
                <Card key={capability.id} className="overflow-hidden">
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between gap-3">
                      <CardTitle className="flex items-center gap-2 text-base"><Icon className="h-4 w-4" />{capability.name}</CardTitle>
                      <Badge variant="outline" className={statusStyles[capability.status]}>{capability.status.replaceAll('_', ' ')}</Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="secondary">{capability.execution}</Badge>
                      <Badge variant="secondary">{capability.safety_tier.replaceAll('_', ' ')}</Badge>
                      <Badge variant="outline">Sections {capability.blueprint_sections.join(', ')}</Badge>
                    </div>
                    <div>
                      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Persisted outputs</div>
                      <div>{capability.outputs.join(' · ')}</div>
                    </div>
                    {capability.prerequisites.length > 0 && (
                      <div className="rounded-md bg-muted/60 p-2 text-xs text-muted-foreground">
                        Requires: {capability.prerequisites.join('; ')}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
