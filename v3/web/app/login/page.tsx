"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { apiFetch } from "../../lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [setup, setSetup] = useState(false);
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);

  useEffect(() => {
    apiFetch("/api/v3/auth/setup-status")
      .then((response) => response.json())
      .then((result) => setSetup(result.setup_required))
      .catch(() => setError("The control plane is unavailable."))
      .finally(() => setChecking(false));
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setWorking(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const payload: Record<string, FormDataEntryValue | null> = { email: form.get("email"), password: form.get("password") };
    if (setup) payload.display_name = form.get("display_name");
    try {
      const response = await apiFetch(setup ? "/api/v3/auth/setup" : "/api/v3/auth/login", { method: "POST", body: JSON.stringify(payload) });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Authentication failed");
      router.replace("/assessments");
      router.refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Authentication failed");
    } finally { setWorking(false); }
  }

  return (
    <main className="loginPage">
      <section className="loginStory"><div className="loginBrand"><span className="brandBlock">ESX</span><strong>ExposureScopeX</strong></div><div className="storyCopy"><p className="kicker">MULTI-AGENT RED TEAM PLATFORM</p><h1>Evidence before <em>assertion.</em></h1><p>Authorized assessment, deterministic execution, independent validation, and defensible reporting in one controlled workspace.</p></div><div className="trustStrip"><span>NO AI IN SCANNING</span><span>NON-EXPLOITATIVE</span><span>CHAIN OF CUSTODY</span></div></section>
      <section className="loginFormWrap"><div className="loginFormHead"><span>{setup ? "INITIAL SETUP" : "SECURE ACCESS"}</span><small>LOCAL / V3 ALPHA</small></div><form className="loginForm" onSubmit={submit}><div><p className="kicker">{setup ? "CREATE WORKSPACE OWNER" : "WELCOME BACK"}</p><h2>{setup ? "Initialize control plane" : "Sign in to operations"}</h2><p>{setup ? "No users exist. Create the first owner account." : "Use your ExposureScopeX operator account."}</p></div>{setup && <label>Display name<input name="display_name" autoComplete="name" required minLength={2} /></label>}<label>Email address<input name="email" type="email" autoComplete="email" required /></label><label>Password<input name="password" type="password" autoComplete={setup ? "new-password" : "current-password"} minLength={12} required /></label>{error && <p className="formError" role="alert">{error}</p>}<button className="primaryAction" disabled={working || checking}>{checking ? "Checking workspace..." : working ? "Verifying..." : setup ? "Create owner account" : "Enter workspace"}</button></form><p className="loginLegal">Authorized operators only. Authentication and security-relevant actions are retained for audit.</p></section>
    </main>
  );
}
