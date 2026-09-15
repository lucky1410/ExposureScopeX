"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect, useState } from "react";

import { apiFetch } from "../lib/api";

type User = { email: string; display_name: string; role: string };
type Theme = "light" | "dark";
type NavItem = { href: string; label: string; mark: string; detail: string };

const primaryNavigation: NavItem[] = [
  { href: "/dashboard", label: "Overview", mark: "01", detail: "Choose a security component" },
  { href: "/assessments", label: "Assessment scans", mark: "02", detail: "Discovery, scans, and lifecycle" },
  { href: "/assets", label: "Asset inventory", mark: "03", detail: "Ownership and coverage" },
  { href: "/operations", label: "Exposure operations", mark: "04", detail: "Lifecycle and monitoring" },
  { href: "/ai-evaluator", label: "PRE-D", mark: "05", detail: "Pre-release AI evaluation" },
  { href: "/reports", label: "Decisions & reports", mark: "06", detail: "Evidence you can share" },
];

const supportingNavigation: NavItem[] = [
  { href: "/findings", label: "Findings", mark: "FI", detail: "Validated observations" },
  { href: "/evidence", label: "Evidence", mark: "EV", detail: "Scope and proof retained" },
  { href: "/settings", label: "Workspace settings", mark: "ST", detail: "Access and policy controls" },
];

function storedTheme(): Theme {
  if (typeof window === "undefined") return "light";
  const saved = window.localStorage.getItem("esx.theme");
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export default function AppShell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>("light");

  useEffect(() => {
    const initialTheme = storedTheme();
    setTheme(initialTheme);
    document.documentElement.dataset.theme = initialTheme;

    apiFetch("/api/v3/auth/me")
      .then(async (response) => {
        if (!response.ok) throw new Error("unauthorized");
        setUser(await response.json());
      })
      .catch(() => router.replace("/login"));
  }, [router]);

  function changeTheme() {
    const nextTheme = theme === "light" ? "dark" : "light";
    setTheme(nextTheme);
    document.documentElement.dataset.theme = nextTheme;
    window.localStorage.setItem("esx.theme", nextTheme);
  }

  async function logout() {
    await apiFetch("/api/v3/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  function nav(items: NavItem[]) {
    return items.map((item) => {
      const active = path === item.href || (item.href !== "/dashboard" && path.startsWith(`${item.href}/`));
      return (
        <Link className={`navItem ${active ? "navItemActive" : ""}`} href={item.href} key={item.href} onClick={() => setOpen(false)}>
          <span className="navMark">{item.mark}</span>
          <span><strong>{item.label}</strong><small>{item.detail}</small></span>
        </Link>
      );
    });
  }

  return (
    <div className="appShell">
      <aside className={`sidebar ${open ? "sidebarOpen" : ""}`}>
        <div className="sideBrand"><span className="brandBlock">ESX</span><div><strong>ExposureScopeX</strong><small>SECURITY ASSURANCE</small></div></div>
        <div className="sideQuickAction"><Link href="/assessments/new" onClick={() => setOpen(false)}>Start a review <span>+</span></Link></div>
        <nav aria-label="Primary navigation">
          <p className="navLabel">WORKSPACE</p>{nav(primaryNavigation)}
          <p className="navLabel">EXPLORE</p>{nav(supportingNavigation.slice(0, 2))}
          <p className="navLabel">MANAGE</p>{nav(supportingNavigation.slice(2))}
        </nav>
        <div className="sideFooter">
          <div className="systemState"><span className="stateDot" /><div><strong>Workspace connected</strong><small>Local control plane</small></div></div>
          <div className="userBlock"><span className="userAvatar">{user?.display_name?.slice(0, 2).toUpperCase() ?? "--"}</span><div><strong>{user?.display_name ?? "Verifying session"}</strong><small>{user?.role ?? ""}</small></div><button onClick={logout} aria-label="Sign out">EXIT</button></div>
        </div>
      </aside>
      <div className="appCanvas">
        <header className="desktopTopbar">
          <div className="workspaceContext"><span className="topbarContext">CURRENT WORKSPACE</span><strong>ExposureScopeX</strong><small>Security assurance, from scope to decision.</small></div>
          <div className="topbarActions"><button className="themeToggle" type="button" onClick={changeTheme} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}><span className="themeToggleIcon" aria-hidden="true">{theme === "light" ? "MO" : "LI"}</span>{theme === "light" ? "DARK" : "LIGHT"}</button><Link className="topbarPrimary" href="/assessments/new">Start review</Link></div>
        </header>
        <header className="mobileHeader"><button onClick={() => setOpen(!open)} aria-label="Toggle navigation">MENU</button><strong>ExposureScopeX</strong><button className="mobileTheme" type="button" onClick={changeTheme} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}>{theme === "light" ? "DARK" : "LIGHT"}</button></header>
        {children}
      </div>
    </div>
  );
}
