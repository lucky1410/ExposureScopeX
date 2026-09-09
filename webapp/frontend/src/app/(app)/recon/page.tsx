'use client'

import { useState } from 'react'
import {
  Globe, Search, Lock, Shield, Server, Copy, Check,
  AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Loader2
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader } from '@/components/shared/page-header'
import { toolDnsLookup, toolWhois, toolSslCheck, toolCrtsh, toolHeadersCheck, toolShodan } from '@/lib/api'

// ── Shared helpers ────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="ml-1 inline-flex items-center text-muted-foreground hover:text-primary"
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  )
}

function ToolInput({ placeholder, onRun, loading }: { placeholder: string; onRun: (v: string) => void; loading: boolean }) {
  const [value, setValue] = useState('')
  return (
    <div className="flex gap-2 max-w-xl">
      <Input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={placeholder}
        onKeyDown={(e) => e.key === 'Enter' && !loading && value.trim() && onRun(value.trim())}
        className="font-mono text-sm"
      />
      <Button onClick={() => value.trim() && onRun(value.trim())} disabled={loading || !value.trim()}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
        {loading ? 'Running...' : 'Run'}
      </Button>
    </div>
  )
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
      <AlertTriangle className="inline h-4 w-4 mr-1" /> {message}
    </div>
  )
}

// ── DNS Lookup ────────────────────────────────────────────────────────────────

function DnsLookup() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async (target: string) => {
    setLoading(true); setError(''); setResult(null)
    try { setResult(await toolDnsLookup(target)) }
    catch (e: any) { setError(e?.response?.data?.detail || 'DNS lookup failed') }
    finally { setLoading(false) }
  }

  const recordColors: Record<string, string> = {
    A: 'bg-blue-500/10 text-blue-400', AAAA: 'bg-purple-500/10 text-purple-400',
    MX: 'bg-orange-500/10 text-orange-400', NS: 'bg-cyan-500/10 text-cyan-400',
    TXT: 'bg-green-500/10 text-green-400', CNAME: 'bg-yellow-500/10 text-yellow-400',
    SOA: 'bg-pink-500/10 text-pink-400', CAA: 'bg-red-500/10 text-red-400',
  }

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-muted-foreground mb-3">Resolve all DNS record types via Cloudflare DoH. Supports A, AAAA, MX, NS, TXT, CNAME, SOA, CAA.</p>
        <ToolInput placeholder="example.com" onRun={run} loading={loading} />
      </div>
      {error && <ErrorBox message={error} />}
      {result && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono">{result.domain}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(result.records as Record<string, string[]>).map(([type, values]) => (
              values.length > 0 && (
                <div key={type}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold font-mono ${recordColors[type] || 'bg-muted text-muted-foreground'}`}>{type}</span>
                    <span className="text-[10px] text-muted-foreground">{values.length} record{values.length > 1 ? 's' : ''}</span>
                  </div>
                  <div className="space-y-1 ml-2">
                    {values.map((v, i) => (
                      <div key={i} className="flex items-center gap-1 font-mono text-xs bg-muted/50 rounded px-2 py-1">
                        <span className="flex-1 break-all">{v}</span>
                        <CopyButton text={v} />
                      </div>
                    ))}
                  </div>
                </div>
              )
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ── WHOIS / RDAP ──────────────────────────────────────────────────────────────

function WhoisLookup() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async (target: string) => {
    setLoading(true); setError(''); setResult(null)
    try { setResult(await toolWhois(target)) }
    catch (e: any) { setError(e?.response?.data?.detail || 'WHOIS lookup failed') }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-muted-foreground mb-3">Domain registration and IP ownership data via RDAP (Registration Data Access Protocol).</p>
        <ToolInput placeholder="example.com or 1.2.3.4" onRun={run} loading={loading} />
      </div>
      {error && <ErrorBox message={error} />}
      {result && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono">{result.target}</CardTitle>
            <CardDescription className="text-[10px] uppercase">{result.type}</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {result.type === 'domain' ? (
                <>
                  {result.domain && <Row label="Domain" value={result.domain} />}
                  {result.registrar && <Row label="Registrar" value={result.registrar} />}
                  {result.registered && <Row label="Registered" value={new Date(result.registered).toLocaleDateString()} />}
                  {result.updated && <Row label="Updated" value={new Date(result.updated).toLocaleDateString()} />}
                  {result.expires && <Row label="Expires" value={new Date(result.expires).toLocaleDateString()} />}
                  {result.nameservers?.length > 0 && (
                    <div className="sm:col-span-2">
                      <dt className="text-[10px] text-muted-foreground uppercase font-medium mb-1">Nameservers</dt>
                      <div className="flex flex-wrap gap-1">
                        {result.nameservers.map((ns: string) => (
                          <Badge key={ns} variant="outline" className="text-[10px] font-mono">{ns}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.status?.length > 0 && (
                    <div className="sm:col-span-2">
                      <dt className="text-[10px] text-muted-foreground uppercase font-medium mb-1">Status</dt>
                      <div className="flex flex-wrap gap-1">
                        {result.status.map((s: string) => (
                          <Badge key={s} variant="secondary" className="text-[10px]">{s}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <>
                  {result.name && <Row label="Network Name" value={result.name} />}
                  {result.handle && <Row label="Handle" value={result.handle} />}
                  {result.country && <Row label="Country" value={result.country} />}
                  {result.start_address && <Row label="Start Address" value={result.start_address} />}
                  {result.end_address && <Row label="End Address" value={result.end_address} />}
                </>
              )}
            </dl>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[10px] text-muted-foreground uppercase font-medium">{label}</dt>
      <dd className="text-sm font-mono mt-0.5 flex items-center gap-1">{value}<CopyButton text={value} /></dd>
    </div>
  )
}

// ── SSL / TLS Checker ─────────────────────────────────────────────────────────

function SslChecker() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async (target: string) => {
    setLoading(true); setError(''); setResult(null)
    try { setResult(await toolSslCheck(target)) }
    catch (e: any) { setError(e?.response?.data?.detail || 'SSL check failed') }
    finally { setLoading(false) }
  }

  const getDaysColor = (days: number | null) => {
    if (days === null) return 'text-muted-foreground'
    if (days < 14) return 'text-red-400'
    if (days < 30) return 'text-orange-400'
    if (days < 90) return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-muted-foreground mb-3">Inspect TLS certificate, cipher suite, protocol version, and expiry for any HTTPS host.</p>
        <ToolInput placeholder="example.com" onRun={run} loading={loading} />
      </div>
      {error && <ErrorBox message={error} />}
      {result && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-mono">{result.host}</CardTitle>
              <div className="flex items-center gap-2">
                <span className={`text-sm font-bold ${getDaysColor(result.days_until_expiry)}`}>
                  {result.days_until_expiry !== null ? `${result.days_until_expiry}d left` : 'N/A'}
                </span>
                {result.warnings?.length === 0
                  ? <CheckCircle className="h-4 w-4 text-green-400" />
                  : <AlertTriangle className="h-4 w-4 text-orange-400" />}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {result.warnings?.length > 0 && (
              <div className="rounded-md border border-orange-500/30 bg-orange-500/10 p-3 space-y-1">
                {result.warnings.map((w: string, i: number) => (
                  <p key={i} className="text-xs text-orange-400"><AlertTriangle className="inline h-3 w-3 mr-1" />{w}</p>
                ))}
              </div>
            )}
            <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {result.subject?.commonName && <Row label="Common Name" value={result.subject.commonName} />}
              {result.issuer?.organizationName && <Row label="Issuer" value={result.issuer.organizationName} />}
              {result.protocol && <Row label="Protocol" value={result.protocol} />}
              {result.cipher && <Row label="Cipher" value={result.cipher} />}
              {result.key_bits && <Row label="Key Bits" value={`${result.key_bits} bits`} />}
              {result.not_before && <Row label="Valid From" value={result.not_before} />}
              {result.not_after && <Row label="Valid Until" value={result.not_after} />}
            </dl>
            {result.san?.length > 0 && (
              <div>
                <p className="text-[10px] text-muted-foreground uppercase font-medium mb-1">Subject Alternative Names ({result.san.length})</p>
                <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                  {result.san.map((s: string) => (
                    <Badge key={s} variant="outline" className="text-[10px] font-mono">{s}</Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ── crt.sh Subdomain Finder ───────────────────────────────────────────────────

function CrtshSearch() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState(false)

  const run = async (target: string) => {
    setLoading(true); setError(''); setResult(null); setFilter('')
    try { setResult(await toolCrtsh(target)) }
    catch (e: any) { setError(e?.response?.data?.detail || 'crt.sh search failed') }
    finally { setLoading(false) }
  }

  const filtered = result?.subdomains?.filter((s: any) =>
    !filter || s.name.includes(filter.toLowerCase())
  ) || []
  const shown = expanded ? filtered : filtered.slice(0, 30)

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-muted-foreground mb-3">Search certificate transparency logs (crt.sh) to discover all subdomains that have ever had an SSL certificate issued.</p>
        <ToolInput placeholder="example.com" onRun={run} loading={loading} />
      </div>
      {error && <ErrorBox message={error} />}
      {result && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Found {result.count} subdomains for <span className="font-mono">{result.domain}</span></CardTitle>
              <Button variant="outline" size="sm" onClick={() => {
                const text = result.subdomains.map((s: any) => s.name).join('\n')
                navigator.clipboard.writeText(text)
              }}>
                <Copy className="h-3 w-3 mr-1" /> Copy All
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input placeholder="Filter subdomains..." value={filter} onChange={(e) => setFilter(e.target.value)} className="h-8 text-xs" />
            <div className="space-y-1 max-h-96 overflow-y-auto">
              {shown.map((s: any) => (
                <div key={s.name} className="flex items-center justify-between rounded px-2 py-1 hover:bg-muted/50 group">
                  <span className="font-mono text-xs text-primary">{s.name}</span>
                  <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    {s.not_after && (
                      <span className="text-[10px] text-muted-foreground">
                        exp: {new Date(s.not_after).toLocaleDateString()}
                      </span>
                    )}
                    <CopyButton text={s.name} />
                  </div>
                </div>
              ))}
            </div>
            {filtered.length > 30 && (
              <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)} className="w-full text-xs">
                {expanded ? <><ChevronUp className="h-3 w-3 mr-1" />Show less</> : <><ChevronDown className="h-3 w-3 mr-1" />Show all {filtered.length} results</>}
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ── HTTP Header Analyzer ──────────────────────────────────────────────────────

function HeaderAnalyzer() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showAll, setShowAll] = useState(false)

  const run = async (target: string) => {
    setLoading(true); setError(''); setResult(null)
    try { setResult(await toolHeadersCheck(target)) }
    catch (e: any) { setError(e?.response?.data?.detail || 'Header check failed') }
    finally { setLoading(false) }
  }

  const scoreColor = (score: number) =>
    score >= 80 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400'

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-muted-foreground mb-3">Fetch HTTP response headers and grade security posture: HSTS, CSP, X-Frame-Options, and more.</p>
        <ToolInput placeholder="https://example.com" onRun={run} loading={loading} />
      </div>
      {error && <ErrorBox message={error} />}
      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-[10px] text-muted-foreground uppercase">Security Score</p>
                <p className={`text-3xl font-bold mt-1 ${scoreColor(result.security_score)}`}>{result.security_score}%</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-[10px] text-muted-foreground uppercase">Status</p>
                <p className="text-2xl font-bold mt-1">{result.status_code}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-[10px] text-muted-foreground uppercase">Info Leaks</p>
                <p className={`text-2xl font-bold mt-1 ${result.info_disclosure?.length > 0 ? 'text-orange-400' : 'text-green-400'}`}>
                  {result.info_disclosure?.length || 0}
                </p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Security Headers</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {result.security_analysis?.map((item: any) => (
                <div key={item.header} className="flex items-start justify-between gap-2 py-1.5 border-b border-border/50 last:border-0">
                  <div className="flex items-center gap-2">
                    {item.present
                      ? <CheckCircle className="h-3.5 w-3.5 text-green-400 shrink-0" />
                      : <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />}
                    <span className="text-sm font-mono">{item.header}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {item.value && (
                      <span className="text-[10px] text-muted-foreground max-w-xs truncate">{item.value}</span>
                    )}
                    {!item.present && item.severity !== 'OK' && (
                      <Badge variant={item.severity === 'HIGH' ? 'destructive' : 'outline'} className="text-[10px]">
                        {item.severity}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {result.info_disclosure?.length > 0 && (
            <Card className="border-orange-500/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-orange-400"><AlertTriangle className="inline h-4 w-4 mr-1" />Information Disclosure</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {result.info_disclosure.map((item: any) => (
                  <div key={item.header} className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] font-mono">{item.header}</Badge>
                    <span className="text-xs text-muted-foreground">{item.value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-2 cursor-pointer" onClick={() => setShowAll(!showAll)}>
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">All Response Headers</CardTitle>
                {showAll ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
            </CardHeader>
            {showAll && (
              <CardContent className="space-y-1">
                {Object.entries(result.all_headers || {}).map(([k, v]) => (
                  <div key={k} className="flex gap-2 text-xs font-mono py-0.5">
                    <span className="text-primary shrink-0">{k}:</span>
                    <span className="text-muted-foreground break-all">{String(v)}</span>
                  </div>
                ))}
              </CardContent>
            )}
          </Card>
        </div>
      )}
    </div>
  )
}

// ── Shodan Search ─────────────────────────────────────────────────────────────

function ShodanSearch() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async (target: string) => {
    setLoading(true); setError(''); setResult(null)
    try { setResult(await toolShodan(target)) }
    catch (e: any) { setError(e?.response?.data?.detail || 'Shodan lookup failed') }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-muted-foreground mb-3">Shodan host intelligence — open ports, services, banners, CVEs, and geolocation. Requires <span className="font-mono text-primary">SHODAN_API_KEY</span> in Settings → API Keys.</p>
        <ToolInput placeholder="1.2.3.4 or example.com" onRun={run} loading={loading} />
      </div>
      {error && <ErrorBox message={error} />}
      {result && !result.found && (
        <div className="rounded-md border p-4 text-sm text-muted-foreground text-center">No Shodan data found for {result.ip}</div>
      )}
      {result && result.found && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Card><CardContent className="p-3 text-center"><p className="text-[10px] text-muted-foreground">Open Ports</p><p className="text-2xl font-bold text-primary">{result.ports?.length || 0}</p></CardContent></Card>
            <Card><CardContent className="p-3 text-center"><p className="text-[10px] text-muted-foreground">Country</p><p className="text-sm font-medium mt-1">{result.country || '—'}</p></CardContent></Card>
            <Card><CardContent className="p-3 text-center"><p className="text-[10px] text-muted-foreground">CVEs</p><p className={`text-2xl font-bold ${result.vulns?.length > 0 ? 'text-red-400' : 'text-green-400'}`}>{result.vulns?.length || 0}</p></CardContent></Card>
            <Card><CardContent className="p-3 text-center"><p className="text-[10px] text-muted-foreground">ISP</p><p className="text-xs mt-1 truncate">{result.isp || '—'}</p></CardContent></Card>
          </div>

          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm">Host Details</CardTitle></CardHeader>
            <CardContent>
              <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {result.organization && <Row label="Organization" value={result.organization} />}
                {result.asn && <Row label="ASN" value={result.asn} />}
                {result.city && <Row label="City" value={result.city} />}
                {result.last_update && <Row label="Last Scan" value={new Date(result.last_update).toLocaleString()} />}
              </dl>
              {result.hostnames?.length > 0 && (
                <div className="mt-3">
                  <p className="text-[10px] text-muted-foreground uppercase font-medium mb-1">Hostnames</p>
                  <div className="flex flex-wrap gap-1">
                    {result.hostnames.map((h: string) => <Badge key={h} variant="outline" className="text-[10px] font-mono">{h}</Badge>)}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {result.vulns?.length > 0 && (
            <Card className="border-red-500/30">
              <CardHeader className="pb-2"><CardTitle className="text-sm text-red-400"><AlertTriangle className="inline h-4 w-4 mr-1" />Known CVEs ({result.vulns.length})</CardTitle></CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1">
                  {result.vulns.map((cve: string) => (
                    <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer">
                      <Badge variant="destructive" className="text-[10px] font-mono hover:opacity-80">{cve}</Badge>
                    </a>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {result.services?.length > 0 && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm"><Server className="inline h-4 w-4 mr-1 text-primary" />Services</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.services.map((svc: any, i: number) => (
                    <div key={i} className="rounded-md border px-3 py-2">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className="text-[10px] font-mono">{svc.port}/{svc.transport}</Badge>
                        {svc.product && <span className="text-xs font-medium">{svc.product}</span>}
                        {svc.version && <span className="text-xs text-muted-foreground">{svc.version}</span>}
                      </div>
                      {svc.banner && <pre className="text-[10px] text-muted-foreground whitespace-pre-wrap max-h-16 overflow-hidden">{svc.banner}</pre>}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ReconPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Recon & OSINT"
        description="Live network intelligence — DNS, WHOIS, SSL, subdomains, headers, Shodan"
      />

      <Tabs defaultValue="dns">
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="dns"><Globe className="h-3.5 w-3.5 mr-1.5" />DNS Lookup</TabsTrigger>
          <TabsTrigger value="whois"><Search className="h-3.5 w-3.5 mr-1.5" />WHOIS</TabsTrigger>
          <TabsTrigger value="ssl"><Lock className="h-3.5 w-3.5 mr-1.5" />SSL/TLS</TabsTrigger>
          <TabsTrigger value="crtsh"><Shield className="h-3.5 w-3.5 mr-1.5" />Subdomains</TabsTrigger>
          <TabsTrigger value="headers"><Server className="h-3.5 w-3.5 mr-1.5" />Headers</TabsTrigger>
          <TabsTrigger value="shodan"><Search className="h-3.5 w-3.5 mr-1.5" />Shodan</TabsTrigger>
        </TabsList>

        <TabsContent value="dns" className="mt-6"><DnsLookup /></TabsContent>
        <TabsContent value="whois" className="mt-6"><WhoisLookup /></TabsContent>
        <TabsContent value="ssl" className="mt-6"><SslChecker /></TabsContent>
        <TabsContent value="crtsh" className="mt-6"><CrtshSearch /></TabsContent>
        <TabsContent value="headers" className="mt-6"><HeaderAnalyzer /></TabsContent>
        <TabsContent value="shodan" className="mt-6"><ShodanSearch /></TabsContent>
      </Tabs>
    </div>
  )
}
