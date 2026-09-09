'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { FileSearch, Shield, StickyNote, Clock, Target, MessageSquare } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader } from '@/components/shared/page-header'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { formatDate, formatRelativeTime } from '@/lib/utils'
import { getInvestigation } from '@/lib/api'
import type { Investigation } from '@/lib/types'

export default function InvestigationDetailPage() {
  const params = useParams()
  const id = params.id as string
  const [investigation, setInvestigation] = useState<Investigation | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    getInvestigation(id)
      .then(setInvestigation)
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

  if (notFound || !investigation) {
    return (
      <div className="flex items-center justify-center py-24">
        <p className="text-sm text-muted-foreground">Investigation not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title={investigation.title} description={investigation.description}>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={investigation.priority} />
          <Badge variant={investigation.status === 'in_progress' ? 'default' : 'outline'} className="capitalize">
            {investigation.status.replace('_', ' ')}
          </Badge>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Priority</p>
            <div className="mt-1"><SeverityBadge severity={investigation.priority} /></div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Assignee</p>
            <p className="text-sm font-medium mt-1">{investigation.assignee || 'Unassigned'}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Findings</p>
            <p className="text-sm font-medium mt-1">{investigation.findings_count}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Created</p>
            <p className="text-sm font-medium mt-1">{formatRelativeTime(investigation.created_at)}</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="evidence">
        <TabsList>
          <TabsTrigger value="evidence">Evidence</TabsTrigger>
          <TabsTrigger value="notes">Notes ({(investigation.notes || []).length})</TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ATT&CK</TabsTrigger>
        </TabsList>

        <TabsContent value="evidence" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FileSearch className="h-4 w-4 text-primary" /> Evidence Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">{investigation.description}</p>
              <div className="flex flex-wrap gap-2">
                {(investigation.tags || []).map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs">{tag}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notes" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <StickyNote className="h-4 w-4 text-primary" /> Investigation Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {(investigation.notes || []).length > 0 ? (
                (investigation.notes || []).map((note) => (
                  <div key={note.id} className="rounded-lg border p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <MessageSquare className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="text-xs font-medium">{note.created_by}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{formatRelativeTime(note.created_at)}</span>
                    </div>
                    <p className="text-sm">{note.content}</p>
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No notes yet</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" /> Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="h-2.5 w-2.5 rounded-full bg-primary" />
                    <div className="w-px flex-1 bg-border" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Investigation created</p>
                    <p className="text-xs text-muted-foreground">{formatDate(investigation.created_at)} by {investigation.created_by}</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="h-2.5 w-2.5 rounded-full bg-green-500" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Last updated</p>
                    <p className="text-xs text-muted-foreground">{formatDate(investigation.updated_at)}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="mitre" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Target className="h-4 w-4 text-primary" /> MITRE ATT&CK Techniques
              </CardTitle>
            </CardHeader>
            <CardContent>
              {(investigation.mitre_techniques || []).length > 0 ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {(investigation.mitre_techniques || []).map((technique) => (
                    <div key={technique} className="rounded-lg border p-3">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs font-mono">{technique}</Badge>
                      </div>
                      <a
                        href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-primary hover:underline mt-1 inline-block"
                      >
                        View on MITRE ATT&CK
                      </a>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No MITRE ATT&CK techniques mapped</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
