'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { ExternalLink, AlertTriangle, Shield, Server } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { formatDate, getRiskScoreColor } from '@/lib/utils'
import { getVulnerability } from '@/lib/api'
import type { Vulnerability } from '@/lib/types'

export default function VulnerabilityDetailPage() {
  const params = useParams()
  const id = params.id as string
  const [vuln, setVuln] = useState<Vulnerability | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    getVulnerability(id)
      .then(setVuln)
      .catch((err) => {
        if (err?.response?.status === 404) setNotFound(true)
        else console.error(err)
      })
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      </div>
    )
  }

  if (notFound || !vuln) {
    return (
      <div className="flex items-center justify-center py-24">
        <p className="text-sm text-muted-foreground">Vulnerability not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title={vuln.cve_id} description={vuln.title}>
        {vuln.is_kev && (
          <Badge variant="destructive" className="gap-1">
            <AlertTriangle className="h-3 w-3" /> Known Exploited
          </Badge>
        )}
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Severity</p>
            <div className="mt-1"><SeverityBadge severity={vuln.severity} /></div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">CVSS Score</p>
            <p className="text-2xl font-bold mt-1" style={{ color: getRiskScoreColor(vuln.cvss_score) }}>
              {vuln.cvss_score.toFixed(1)}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">EPSS Score</p>
            <p className="text-2xl font-bold mt-1 text-primary">{(vuln.epss_score * 100).toFixed(1)}%</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Exploit</p>
            <div className="mt-2">
              {vuln.exploit_available ? (
                <Badge variant="destructive">Available</Badge>
              ) : (
                <Badge variant="outline">None Known</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" /> Vulnerability Details
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-xs text-muted-foreground mb-1">Description</p>
              <p className="text-sm">{vuln.description}</p>
            </div>
            {vuln.cvss_vector && (
              <div>
                <p className="text-xs text-muted-foreground mb-1">CVSS Vector</p>
                <code className="text-xs bg-muted px-2 py-1 rounded font-mono">{vuln.cvss_vector}</code>
              </div>
            )}
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Published</span>
              <span>{formatDate(vuln.published_date)}</span>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          {vuln.remediation && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Remediation</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{vuln.remediation}</p>
              </CardContent>
            </Card>
          )}

          {vuln.affected_assets && vuln.affected_assets.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="h-4 w-4 text-primary" /> Affected Assets
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {vuln.affected_assets.map((asset) => (
                    <div key={asset} className="flex items-center justify-between rounded-md border p-2">
                      <span className="font-mono text-sm text-primary">{asset}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {vuln.references && vuln.references.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">References</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {vuln.references.map((ref) => (
                    <a key={ref} href={ref} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-sm text-primary hover:underline">
                      <ExternalLink className="h-3 w-3" /> {ref}
                    </a>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
