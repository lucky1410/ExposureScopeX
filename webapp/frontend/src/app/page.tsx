import Link from 'next/link'
import Image from 'next/image'
import { ArrowRight, Compass, Radar, ShieldCheck, Waypoints } from 'lucide-react'

const featureRows = [
  {
    title: 'External attack surface, normalized',
    body: 'Turn scattered recon, benchmark data, archived endpoints, exposed services, and vulnerability signals into one operating picture.',
  },
  {
    title: 'Scoring with evidence behind it',
    body: 'Every risk tier, benchmark, and drift signal is tied to observable infrastructure, endpoints, findings, and historical changes.',
  },
  {
    title: 'Built for operators, not demos',
    body: 'ASM, bug hunting, recon, findings, and reporting live inside one consistent shell so the platform feels like a real security workflow.',
  },
]

const moduleCards = [
  {
    title: 'Recon & OSINT',
    text: 'DNS, headers, certificates, Wayback, Shodan, and discovery intelligence.',
    icon: Compass,
  },
  {
    title: 'ASM Control',
    text: 'Inventory, cloud sources, rescans, findings, and profile-normalized targeting.',
    icon: Waypoints,
  },
  {
    title: 'Exposure Benchmarks',
    text: 'Risk scoring, drift, notable changes, and evidence correlation.',
    icon: ShieldCheck,
  },
]

export default function Home() {
  return (
    <main className="min-h-screen px-4 py-6 sm:px-6 lg:px-10">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <section className="brand-panel relative overflow-hidden px-6 py-6 sm:px-10 sm:py-10">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/60 to-transparent" />
          <div className="flex flex-col gap-10 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl space-y-6">
              <p className="metric-kicker">ExposureScopeX Intelligence Platform</p>
              <h1 className="editorial-title">
                Monitor external exposure like it deserves its own command center.
              </h1>
              <p className="editorial-subtitle">
                ExposureScopeX unifies reconnaissance, attack-surface monitoring, vulnerability evidence,
                benchmark context, and operator workflows into one continuously updated platform.
              </p>
              <div className="flex flex-wrap gap-3">
                <Link
                  href="/login"
                  className="inline-flex items-center gap-2 rounded-full bg-primary px-5 py-3 text-sm font-semibold text-primary-foreground transition-transform hover:-translate-y-0.5"
                >
                  Enter Platform <ArrowRight className="h-4 w-4" />
                </Link>
                <Link
                  href="/register"
                  className="inline-flex items-center gap-2 rounded-full border border-border bg-background/70 px-5 py-3 text-sm font-semibold"
                >
                  Create Workspace
                </Link>
              </div>
            </div>
            <div className="grid min-w-[280px] gap-3 sm:grid-cols-3 lg:w-[420px] lg:grid-cols-1">
              <div className="rounded-[1.4rem] border border-border/70 bg-background/80 p-4">
                <p className="metric-kicker">Risk Benchmark</p>
                <p className="mt-3 text-5xl font-semibold tracking-[-0.05em]">742</p>
                <p className="mt-2 text-sm text-muted-foreground">Up 18 points over the last 30 days</p>
              </div>
              <div className="rounded-[1.4rem] border border-border/70 bg-background/80 p-4">
                <p className="metric-kicker">Active Surface</p>
                <p className="mt-3 text-2xl font-semibold">238 assets</p>
                <p className="mt-2 text-sm text-muted-foreground">Domains, services, archived endpoints, and cloud assets under watch</p>
              </div>
              <div className="rounded-[1.4rem] border border-border/70 bg-background/80 p-4">
                <p className="metric-kicker">Live Intelligence</p>
                <p className="mt-3 text-2xl font-semibold">Nuclei + Recon</p>
                <p className="mt-2 text-sm text-muted-foreground">Template-driven evidence, historical discovery, and operator-ready findings</p>
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="brand-panel p-6 sm:p-8">
            <div className="mb-8 flex items-center gap-3">
              <div className="rounded-2xl bg-primary/12 p-3 text-primary"><Radar className="h-5 w-5" /></div>
              <div>
                <p className="metric-kicker">Platform Direction</p>
                <h2 className="text-2xl font-semibold tracking-[-0.03em]">One surface, many operating modes</h2>
              </div>
            </div>
            <div className="space-y-6">
              {featureRows.map((item) => (
                <div key={item.title} className="border-b border-border/60 pb-6 last:border-b-0 last:pb-0">
                  <h3 className="text-lg font-semibold">{item.title}</h3>
                  <p className="mt-2 max-w-2xl text-sm leading-7 text-muted-foreground">{item.body}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="brand-panel p-6 sm:p-8">
            <p className="metric-kicker">Core Modules</p>
            <div className="mt-5 space-y-4">
              {moduleCards.map((item) => (
                <div key={item.title} className="rounded-[1.3rem] border border-border/70 bg-background/70 p-4">
                  <div className="flex items-start gap-3">
                    <div className="rounded-xl bg-primary/10 p-2 text-primary"><item.icon className="h-4 w-4" /></div>
                    <div>
                      <h3 className="text-sm font-semibold">{item.title}</h3>
                      <p className="mt-1 text-sm leading-6 text-muted-foreground">{item.text}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="brand-panel overflow-hidden p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-2xl">
              <p className="metric-kicker">Visual Identity</p>
              <h2 className="mt-3 text-3xl font-semibold tracking-[-0.03em]">A warmer, more editorial security surface.</h2>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">
                Inspired by the quiet confidence of the reference site, but adapted for operational
                security work: softer contrast, more breathing room, stronger hierarchy, and clearer data framing.
              </p>
            </div>
            <Image
              src="/images/full-logo.png"
              alt="ExposureScopeX visual mark"
              width={180}
              height={180}
              className="h-28 w-28 self-start object-contain drop-shadow-[0_24px_44px_rgba(255,112,45,0.22)] sm:h-36 sm:w-36 lg:self-auto"
              priority
            />
          </div>
        </section>
      </div>
    </main>
  )
}
