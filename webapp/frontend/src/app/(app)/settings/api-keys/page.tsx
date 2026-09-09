'use client'

import { useEffect, useState } from 'react'
import axios from 'axios'
import { Key, Plus, Trash2, CheckCircle, XCircle, Eye, EyeOff } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogTrigger,
} from '@/components/ui/dialog'
import { useToast } from '@/components/ui/use-toast'
import { PageHeader } from '@/components/shared/page-header'
import { formatDate, formatRelativeTime } from '@/lib/utils'
import { getApiKeys, saveApiKey, deleteApiKey } from '@/lib/api'
import type { ApiKey } from '@/lib/types'

const services = [
  { value: 'shodan', label: 'Shodan' },
  { value: 'virustotal', label: 'VirusTotal' },
  { value: 'censys', label: 'Censys' },
  { value: 'hibp', label: 'Have I Been Pwned' },
  { value: 'anthropic', label: 'Anthropic (AI Agent)' },
  { value: 'github', label: 'GitHub Token' },
  { value: 'slack', label: 'Slack Webhook' },
  { value: 'teams', label: 'Teams Webhook' },
  { value: 'splunk', label: 'Splunk HEC' },
]

export default function ApiKeysPage() {
  const { toast } = useToast()
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [newKey, setNewKey] = useState({ name: '', service: '', key: '' })
  const [showKey, setShowKey] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getApiKeys()
      .then(setKeys)
      .catch((err) => {
        toast({
          title: 'Could not load API keys',
          description: axios.isAxiosError(err) ? err.response?.data?.detail || err.message : 'Unknown error',
          variant: 'destructive',
        })
      })
      .finally(() => setLoading(false))
  }, [toast])

  const handleAdd = async () => {
    if (!newKey.name || !newKey.service || !newKey.key) return
    setSaving(true)
    try {
      const created = await saveApiKey(newKey)
      setKeys((prev) => [...prev, created])
      setNewKey({ name: '', service: '', key: '' })
      setDialogOpen(false)
      toast({
        title: 'API key saved',
        description: `${created.name} was added successfully.`,
      })
    } catch (err) {
      toast({
        title: 'Could not save API key',
        description: axios.isAxiosError(err) ? err.response?.data?.detail || err.message : 'Unknown error',
        variant: 'destructive',
      })
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this API key?')) return
    try {
      await deleteApiKey(id)
      setKeys((prev) => prev.filter((k) => k.id !== id))
      toast({
        title: 'API key deleted',
        description: 'The API key was removed successfully.',
      })
    } catch (err) {
      toast({
        title: 'Could not delete API key',
        description: axios.isAxiosError(err) ? err.response?.data?.detail || err.message : 'Unknown error',
        variant: 'destructive',
      })
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="API Keys" description="Manage API keys for third-party service integrations">
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" /> Add API Key
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add API Key</DialogTitle>
              <DialogDescription>Add a new API key for service integration</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input placeholder="e.g., Production Shodan Key" value={newKey.name} onChange={(e) => setNewKey({ ...newKey, name: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>Service</Label>
                <Select value={newKey.service} onValueChange={(v) => setNewKey({ ...newKey, service: v })}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select service" />
                  </SelectTrigger>
                  <SelectContent>
                    {services.map((s) => (
                      <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>API Key</Label>
                <div className="relative">
                  <Input
                    type={showKey ? 'text' : 'password'}
                    placeholder="Enter API key"
                    value={newKey.key}
                    onChange={(e) => setNewKey({ ...newKey, key: e.target.value })}
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
              <Button onClick={handleAdd} disabled={!newKey.name || !newKey.service || !newKey.key || saving}>
                {saving ? 'Saving...' : 'Add Key'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </PageHeader>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Key className="h-4 w-4 text-primary" /> Configured API Keys
          </CardTitle>
          <CardDescription>API keys are encrypted at rest. Only key previews are shown.</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : keys.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No API keys configured</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Key</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((apiKey) => (
                  <TableRow key={apiKey.id}>
                    <TableCell className="font-medium text-sm">{apiKey.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-[10px] capitalize">{apiKey.service}</Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-2 py-0.5 rounded font-mono">{apiKey.key_preview}</code>
                    </TableCell>
                    <TableCell>
                      {apiKey.is_valid ? (
                        <div className="flex items-center gap-1 text-green-400">
                          <CheckCircle className="h-3.5 w-3.5" />
                          <span className="text-xs">Valid</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 text-red-400">
                          <XCircle className="h-3.5 w-3.5" />
                          <span className="text-xs">Invalid</span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatDate(apiKey.created_at)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {apiKey.last_used ? formatRelativeTime(apiKey.last_used) : 'Never'}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => handleDelete(apiKey.id)} className="text-destructive hover:text-destructive">
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
