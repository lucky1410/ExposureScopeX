'use client'

import { useCallback, useEffect, useState } from 'react'
import { Download, Search } from 'lucide-react'
import { exportAuditLogs, getAuditLogs, type AuditLogEntry } from '@/lib/api'
import { PageHeader } from '@/components/shared/page-header'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'

export default function AuditLogsPage() {
  const [items, setItems] = useState<AuditLogEntry[]>([])
  const [search, setSearch] = useState('')
  const [action, setAction] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const result = await getAuditLogs({ search: search || undefined, action: action || undefined, page_size: 200 })
      setItems(result.items)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load the audit log')
    } finally {
      setLoading(false)
    }
  }, [action, search])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-6">
      <PageHeader title="Audit Log" description="Organization-scoped security and administrative activity" />
      <Card>
        <CardContent className="space-y-4 pt-6">
          <div className="flex flex-col gap-3 md:flex-row">
            <div className="relative flex-1"><Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" /><Input className="pl-9" placeholder="Search actor, action, entity, or IP" value={search} onChange={(event) => setSearch(event.target.value)} /></div>
            <Input className="md:w-64" placeholder="Action filter, e.g. scan.start" value={action} onChange={(event) => setAction(event.target.value)} />
            <Button variant="outline" onClick={() => exportAuditLogs({ search: search || undefined, action: action || undefined })}><Download className="mr-2 h-4 w-4" />Export CSV</Button>
          </div>
          {error ? <p className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{error}</p> : null}
          <div className="overflow-x-auto rounded-xl border">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground"><tr><th className="p-3">Time</th><th className="p-3">Action</th><th className="p-3">Actor</th><th className="p-3">Entity</th><th className="p-3">Result</th><th className="p-3">Source</th></tr></thead>
              <tbody>
                {items.map((item) => <tr key={item.id} className="border-t"><td className="whitespace-nowrap p-3">{new Date(item.created_at).toLocaleString()}</td><td className="p-3 font-mono text-xs">{item.action}</td><td className="p-3">{item.actor || 'System'}</td><td className="p-3">{item.entity_type || '-'}{item.entity_id ? <span className="ml-1 font-mono text-xs text-muted-foreground">{item.entity_id.slice(0, 8)}</span> : null}</td><td className="p-3"><Badge variant={item.success ? 'secondary' : 'destructive'}>{item.success ? 'Success' : 'Failed'}</Badge></td><td className="p-3 font-mono text-xs">{item.ip_address || '-'}</td></tr>)}
                {!loading && items.length === 0 ? <tr><td colSpan={6} className="p-8 text-center text-muted-foreground">No matching audit events.</td></tr> : null}
              </tbody>
            </table>
          </div>
          {loading ? <p className="text-sm text-muted-foreground">Loading audit events...</p> : null}
        </CardContent>
      </Card>
    </div>
  )
}
