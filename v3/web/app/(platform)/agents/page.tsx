"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "../../../lib/api";

type Agent = {
  id: string;
  name: string;
  domain: string;
  version: string;
  runtime: string;
  safety_class: string;
  capabilities: string[];
  logical_roles?: string[];
  may_control_scanners: boolean;
  status: "active" | "planned";
};

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    apiFetch("/api/v3/agents")
      .then(async (response) => {
        if (!response.ok) throw new Error("Agent control plane is unavailable");
        setAgents(await response.json());
      })
      .catch((reason: Error) => setError(reason.message));
  }, []);

  const active = agents.filter((agent) => agent.status === "active").length;
  const domains = new Set(agents.map((agent) => agent.domain)).size;

  return (
    <main className="workspacePage">
      <header className="pageHeader">
        <div><p className="kicker">GOVERNED MULTI-AGENT SYSTEM</p><h1>Agent registry</h1><p>Versioned specialist agents, explicit authority boundaries, and independently measured quality.</p></div>
        <span className="moduleStatus">{active} active · {agents.length - active} planned</span>
      </header>
      {error && <p className="formError">{error}</p>}

      <section className="agentSummary">
        <div><span>REGISTERED</span><strong>{agents.length}</strong></div>
        <div><span>DOMAINS</span><strong>{domains}</strong></div>
        <div><span>ACTIVE</span><strong>{active}</strong></div>
        <div><span>AI SCANNER CONTROL</span><strong>0</strong><small>Hard policy boundary</small></div>
      </section>

      <section className="registrySection">
        <header><div><h2>Specialist inventory</h2><p>Runtime and scanner authority are declared per immutable agent version.</p></div></header>
        <div className="agentGrid">{agents.map((agent) => (
          <article className="agentCard" key={agent.id}>
            <div className="agentCardTop"><span>{agent.domain}</span><i className={`agentStatus agentStatus-${agent.status}`}>{agent.status}</i></div>
            <h3>{agent.name}</h3><p>{agent.capabilities.join(" · ")}</p>
            {(agent.logical_roles?.length ?? 0) > 0 && <small>Roles: {agent.logical_roles?.join(" · ")}</small>}
            <footer><span>{agent.runtime}</span><span>v{agent.version}</span><span>{agent.may_control_scanners ? "bounded scanner control" : "no scanner control"}</span></footer>
          </article>
        ))}</div>
      </section>

    </main>
  );
}
