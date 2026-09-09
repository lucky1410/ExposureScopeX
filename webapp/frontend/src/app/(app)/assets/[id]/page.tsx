'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { Globe, Shield, Server, Lock, Bug, Clock, Cpu, Network } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { PageHeader } from '@/components/shared/page-header'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { StatusIndicator } from '@/components/shared/status-indicator'
import { formatDate } from '@/lib/utils'
import { getAsset, getFindings } from '@/lib/api'

export default function AssetDetailPage() {
  const params = useParams()
  const id = params.id as string
  const [asset, setAsset] = useState<any>(null)
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      getAsset(id) as Promise<any>,
      getFindings({ page_size: 100 }).catch(() => ({ items: [] })),
    ])
      .then(([assetData, findingsData]) => {
        const mapped = {
          ...assetData,
          type: assetData.asset_type || assetData.type || 'unknown',
          status: assetData.is_live === true ? 'live' : assetData.is_live === false ? 'dead' : (assetData.status || 'unknown'),
          ports: assetData.ports || [],
          dns_records: assetData.dns_records || [],
          technologies: assetData.technologies || [],
          tls_certificate: (assetData.tls_certificates && assetData.tls_certificates.length > 0)
            ? assetData.tls_certificates[0]
            : (assetData.tls_certificate || null),
        }
        setAsset(mapped)
        const assetFindings = findingsData.items.filter((f: any) => f.asset_id === id)
        setFindings(assetFindings)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      </div>
    )
  }

  if (!asset) {
    return (
      <div className="flex items-center justify-center py-24">
        <p className="text-sm text-muted-foreground">Asset not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={asset.value}
        description={`${asset.type} asset — First seen ${formatDate(asset.first_seen)}`}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                <Globe className="h-4 w-4 text-primary" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Type</p>
                <p className="text-sm font-medium capitalize">{asset.type}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <StatusIndicator status={asset.status === 'live' ? 'success' : 'error'} />
              <div>
                <p className="text-xs text-muted-foreground">Status</p>
                <p className="text-sm font-medium capitalize">{asset.status}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-orange-500/10">
                <Bug className="h-4 w-4 text-orange-400" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Findings</p>
                <p className="text-sm font-medium">{findings.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                <Shield className="h-4 w-4 text-primary" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Ports Open</p>
                <p className="text-sm font-medium">{asset.ports.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="dns">DNS Records</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="technologies">Technologies</TabsTrigger>
          <TabsTrigger value="tls">TLS</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Findings</TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="h-4 w-4 text-primary" /> Asset Information
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  ['Value', asset.value],
                  ['Type', asset.type],
                  ['First Seen', formatDate(asset.first_seen)],
                  ['Last Seen', formatDate(asset.last_seen)],
                  ['Open Ports', String(asset.ports.length)],
                  ['Technologies', String(asset.technologies.length)],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{label}</span>
                    <span className="font-mono text-xs capitalize">{value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-primary" /> Technology Stack
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {asset.technologies.map((tech: any) => (
                    <Badge key={tech.id} variant="secondary">
                      {tech.name}{tech.version ? ` ${tech.version}` : ''}
                      {tech.category && <span className="ml-1.5 text-[10px] text-muted-foreground">{tech.category}</span>}
                    </Badge>
                  ))}
                  {asset.technologies.length === 0 && (
                    <p className="text-sm text-muted-foreground">No technologies detected</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="dns">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Network className="h-4 w-4 text-primary" /> DNS Records
              </CardTitle>
            </CardHeader>
            <CardContent>
              {asset.dns_records.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead>TTL</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {asset.dns_records.map((record: any) => (
                      <TableRow key={record.id}>
                        <TableCell><Badge variant="outline" className="text-xs">{record.record_type}</Badge></TableCell>
                        <TableCell className="font-mono text-sm">{record.name}</TableCell>
                        <TableCell className="font-mono text-sm">{record.value}</TableCell>
                        <TableCell className="text-muted-foreground">{record.ttl}s</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No DNS records found</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ports">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Server className="h-4 w-4 text-primary" /> Open Ports
              </CardTitle>
            </CardHeader>
            <CardContent>
              {asset.ports.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Port</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>State</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>Version</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {asset.ports.map((port: any) => (
                      <TableRow key={port.id}>
                        <TableCell className="font-mono font-medium">{port.port_number}</TableCell>
                        <TableCell className="uppercase text-xs">{port.protocol}</TableCell>
                        <TableCell>
                          <StatusIndicator status={port.state === 'open' ? 'success' : port.state === 'filtered' ? 'pending' : 'error'} label={port.state} />
                        </TableCell>
                        <TableCell>{port.service}</TableCell>
                        <TableCell className="text-muted-foreground">{port.version || '--'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No ports scanned</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="technologies">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Cpu className="h-4 w-4 text-primary" /> Detected Technologies
              </CardTitle>
            </CardHeader>
            <CardContent>
              {asset.technologies.length > 0 ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {asset.technologies.map((tech: any) => (
                    <div key={tech.id} className="rounded-lg border p-3">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-sm">{tech.name}</span>
                        {tech.version && <Badge variant="outline" className="text-[10px]">v{tech.version}</Badge>}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{tech.category}</p>
                      {tech.confidence !== undefined && (
                        <>
                          <div className="mt-2 h-1.5 w-full rounded-full bg-muted">
                            <div className="h-1.5 rounded-full bg-primary" style={{ width: `${tech.confidence}%` }} />
                          </div>
                          <p className="text-[10px] text-muted-foreground mt-1">{tech.confidence}% confidence</p>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No technologies detected</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="tls">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Lock className="h-4 w-4 text-primary" /> TLS Certificate
              </CardTitle>
            </CardHeader>
            <CardContent>
              {asset.tls_certificate ? (
                <div className="space-y-3">
                  {[
                    ['Subject', asset.tls_certificate.subject],
                    ['Issuer', asset.tls_certificate.issuer],
                    ['Valid From', formatDate(asset.tls_certificate.not_before)],
                    ['Valid Until', formatDate(asset.tls_certificate.not_after)],
                    ['Days Until Expiry', `${asset.tls_certificate.days_until_expiry} days`],
                  ].map(([label, value]) => (
                    <div key={label} className="flex justify-between text-sm">
                      <span className="text-muted-foreground">{label}</span>
                      <span className="font-mono text-xs">{value}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No TLS certificate information available</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vulnerabilities">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Bug className="h-4 w-4 text-primary" /> Findings
              </CardTitle>
            </CardHeader>
            <CardContent>
              {findings.length > 0 ? (
                <div className="space-y-3">
                  {findings.map((finding: any) => (
                    <div key={finding.id} className="rounded-lg border p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={finding.severity} />
                        <span className="font-medium text-sm">{finding.title}</span>
                      </div>
                      <p className="text-xs text-muted-foreground">{finding.description?.substring(0, 120)}...</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No findings for this asset</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" /> Change History
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
                    <p className="text-sm font-medium">Asset discovered</p>
                    <p className="text-xs text-muted-foreground">{formatDate(asset.first_seen)}</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="h-2.5 w-2.5 rounded-full bg-green-500" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Last confirmed</p>
                    <p className="text-xs text-muted-foreground">{formatDate(asset.last_seen)}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
