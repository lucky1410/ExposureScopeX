"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect, useState } from "react";

import { apiFetch } from "../lib/api";

type User = { email: string; display_name: string; role: string };
type NavItem = { href: string; label: string; mark: string; planned?: boolean };

const primaryNavigation: NavItem[] = [
  { href: "/dashboard", label: "Command overview", mark: "CO" },
  { href: "/assessments", label: "Assessments", mark: "AS" },
  { href: "/scans", label: "Scan operations", mark: "SC" },
  { href: "/findings", label: "Findings", mark: "FI" },
];

const intelligenceNavigation: NavItem[] = [
  { href: "/assets", label: "Asset inventory", mark: "AI" },
  { href: "/vulnerabilities", label: "Vulnerabilities", mark: "VU" },
  { href: "/risk-paths", label: "Risk paths", mark: "RG" },
];

const evidenceNavigation: NavItem[] = [
  { href: "/evidence", label: "Evidence", mark: "EV" },
  { href: "/reports", label: "Reports", mark: "RP" },
  { href: "/ai-evaluator", label: "AI assurance", mark: "AA" },
  { href: "/agents", label: "Agent registry", mark: "AG" },
  { href: "/benchmarks", label: "Benchmarks", mark: "BM" },
];

const systemNavigation: NavItem[] = [
  { href: "/runtime", label: "Runtime", mark: "RT" },
  { href: "/settings", label: "Settings", mark: "ST" },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    apiFetch("/api/v3/auth/me")
      .then(async (response) => {
        if (!response.ok) throw new Error("unauthorized");
        setUser(await response.json());
      })
      .catch(() => router.replace("/login"));
  }, [router]);

  async function logout() {
    await apiFetch("/api/v3/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  function nav(items: NavItem[]) {
    return items.map((item) => {
      if (item.planned) {
        return <span className="navItem navItemPlanned" key={item.href} aria-disabled="true"><span className="navMark">{item.mark}</span><span>{item.label}</span><small>SOON</small></span>;
      }
      const active = path.startsWith(item.href);
      return <Link className={`navItem ${active ? "navItemActive" : ""}`} href={item.href} key={item.href} onClick={() => setOpen(false)}><span className="navMark">{item.mark}</span><span>{item.label}</span></Link>;
    });
  }

  return (
    <div className="appShell">
      <aside className={`sidebar ${open ? "sidebarOpen" : ""}`}>
        <div className="sideBrand"><span className="brandBlock">ESX</span><div><strong>ExposureScopeX</strong><small>RED TEAM CONTROL</small></div></div>
        <nav aria-label="Primary navigation"><p className="navLabel">COMMAND</p>{nav(primaryNavigation)}<p className="navLabel">INTELLIGENCE</p>{nav(intelligenceNavigation)}<p className="navLabel">EVIDENCE & ASSURANCE</p>{nav(evidenceNavigation)}<p className="navLabel">SYSTEM</p>{nav(systemNavigation)}</nav>
        <div className="sideFooter">
          <div className="systemState"><span className="stateDot" /><div><strong>Local control plane</strong><small>Deterministic execution</small></div></div>
          <div className="userBlock"><span className="userAvatar">{user?.display_name?.slice(0, 2).toUpperCase() ?? "--"}</span><div><strong>{user?.display_name ?? "Verifying session"}</strong><small>{user?.role ?? ""}</small></div><button onClick={logout} aria-label="Sign out">EXIT</button></div>
        </div>
      </aside>
      <div className="appCanvas">
        <header className="desktopTopbar"><div><span className="topbarContext">OPERATIONS CONSOLE</span><small>Assessment integrity and execution telemetry</small></div><div className="topbarSearch">Search assessments, findings, evidence <kbd>CTRL K</kbd></div><div className="topbarMode"><span className="stateDot" />LOCAL</div></header>
        <header className="mobileHeader"><button onClick={() => setOpen(!open)} aria-label="Toggle navigation">MENU</button><strong>ExposureScopeX</strong><span>V3</span></header>{children}
      </div>
    </div>
  );
}
