"""Local setup page for the customer-facing HTTP evaluation workflow."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import webbrowser
from typing import Any
from urllib.parse import urlparse

from .assurance import build_risk_plan, create_scope
from .discovery import discover_repository
from .profiles import PROFILE_NAMES, build_cases, profile
from .runner import CONFIG_SCHEMA_VERSION, _is_loopback_host


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,62}$")


def create_http_plan(values: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Backward-compatible entry point for an editable HTTP plan."""
    return create_guided_plan({**values, "connection_type": "http", "confirm_plan": True})


def create_guided_plan(values: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Create one self-contained, customer-confirmed local evaluation workflow."""
    for key in ("directory", "agent_id", "subject_version", "project_key", "url"):
        if not isinstance(values.get(key), str) or not values[key].strip():
            raise ValueError(f"{key.replace('_', ' ')} is required")
    if not _IDENTIFIER.fullmatch(values["agent_id"]) or not _IDENTIFIER.fullmatch(values["project_key"]):
        raise ValueError("Application ID and project key must use lowercase letters, digits, and hyphens")
    profile_name = values.get("profile", "smoke")
    if profile_name not in PROFILE_NAMES:
        raise ValueError("Choose a valid evaluation profile")
    additions = values.get("custom_cases", [])
    if not isinstance(additions, list):
        raise ValueError("Additional cases must be a JSON array")
    connection_type = values.get("connection_type", "http")
    if connection_type not in {"http", "browser"}:
        raise ValueError("Choose an HTTP API or browser journey connection")
    target = Path(values["directory"]).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        raise ValueError(f"Refusing to overwrite non-empty folder: {target}")
    dataset_version = f"{values['agent_id']}-{profile_name}-1.0"
    host = urlparse(values["url"]).hostname or ""
    if connection_type == "browser" and not _is_loopback_host(host):
        raise ValueError("Browser journeys can use a loopback URL only")
    target_environment = "local" if _is_loopback_host(host) else "staging"
    discovery = values.get("discovery")
    if discovery is not None and not isinstance(discovery, dict):
        raise ValueError("Discovery data is invalid; scan the repository again")
    selected_ids = values.get("selected_component_ids", [])
    if not isinstance(selected_ids, list) or not all(isinstance(item, str) for item in selected_ids):
        raise ValueError("Selected components are invalid")
    if discovery and discovery.get("components"):
        if not selected_ids:
            raise ValueError("Select at least one discovered component that is approved for evaluation")
        scope = create_scope(discovery, selected_ids)
    else:
        workflow_id = f"workflow-{values['agent_id']}"
        discovery = {
            "status": "not_scanned",
            "repository": None,
            "components": [{"id": workflow_id, "name": f"Declared workflow: {values['agent_id']}", "kind": "workflow_entry_point", "confidence": "customer_declared"}],
            "limitations": "No repository scan was requested. Scope contains only the customer-declared workflow.",
        }
        scope = create_scope(discovery, [workflow_id])
    plan = build_risk_plan(scope, profile_name)
    if values.get("confirm_plan") is not True:
        raise ValueError("Confirm the reviewed scope and plan before creating the local evaluation")
    plan["status"] = "customer_confirmed"
    plan["confirmation"] = "confirmed_in_local_setup"
    if connection_type == "browser":
        path = values.get("browser_path", "/")
        expected_text = values.get("browser_expected_text", "")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Browser start path must start with /")
        if not isinstance(expected_text, str) or not expected_text.strip():
            raise ValueError("Browser expected text is required")
        cases = [{
            "case_id": "browser-journey-001",
            "input": {"journey": [{"type": "goto", "path": path}, {"type": "expect_text", "value": expected_text.strip()}]},
            "expected_label": "pass",
        }]
        adapter: dict[str, Any] = {"type": "browser_journey", "base_url": values["url"], "pass_label": "pass", "fail_label": "fail", "timeout_seconds": 60}
    else:
        cases = build_cases(profile_name, additions)
        adapter = {"type": "http_json_target", "url": values["url"], "request_mode": values.get("request_mode", "message"), "response_label_path": values.get("response_label_path", "decision.label"), "response_confidence_path": values.get("response_confidence_path", "decision.confidence"), "timeout_seconds": 60, "allow_remote": bool(values.get("allow_remote")), "target_environment": target_environment, "max_cases": 500, "minimum_delay_ms": 100}
    config = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "evaluation": {"name": f"{values['agent_id']} {profile(profile_name)['name'].lower()}", "agent_id": values["agent_id"], "subject_version": values["subject_version"], "subject_type": values.get("subject_type", "agent"), "project_key": values["project_key"], "dataset_version": dataset_version, "required_dimensions": ["classification", "confidence"]},
        "dataset": {"version": dataset_version, "cases": cases},
        "adapter": adapter,
        "source": {"origin": "local"},
        "plan": {"profile": profile_name, "profile_description": profile(profile_name)["description"], "review_required": False},
        "assurance": {"discovery_file": "discovery.json", "scope_file": "assurance-scope.json", "plan_file": "risk-plan.json", "telemetry_file": "out/telemetry.jsonl", "planned_dimensions": plan["required_dimensions"]},
    }
    target.mkdir(parents=True, exist_ok=True)
    path = target / "esx-eval.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (target / "discovery.json").write_text(json.dumps(discovery, indent=2) + "\n", encoding="utf-8")
    (target / "assurance-scope.json").write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    (target / "risk-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    (target / "README.md").write_text(_plan_readme(config, plan), encoding="utf-8")
    return path, config


def _plan_readme(config: dict[str, Any], plan: dict[str, Any] | None = None) -> str:
    adapter = config["adapter"]
    staging_note = ""
    if adapter["target_environment"] == "staging":
        staging_note = '''

## Required staging security configuration

This plan cannot run against a remote target until the `adapter` configuration
also includes mTLS `client_certificate_path` and `client_private_key_path`, plus
a signed `target_attestation`. The attestation endpoint must be on the same
HTTPS host and prove that this is a synthetic-data test tenant with production
actions disabled. See the runner's `README.md` Security boundary section before
adding those values. Do not downgrade this target to plain HTTP.
'''
    return f'''# Local pre-release evaluation

This folder was generated locally by `esx-eval setup`. It evaluates a customer-owned HTTP application without uploading prompts, responses, source code, credentials, or results.

## Run this plan

1. Start the application locally, or use an approved staging URL.
2. Open `esx-eval.json` and review every labelled test case. Replace, remove, or add cases to match the product's real requirements.
3. The runner sends `{{"message": "..."}}` to `{adapter['url']}`. It reads the decision label from `{adapter['response_label_path']}` and a numeric confidence from `{adapter['response_confidence_path']}`.
4. Run:

```powershell
esx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json
esx-eval view --report .\\out\\evaluation.local-report.html
```

The terminal and HTML report are private and local. A successful smoke plan proves only this connection and the selected labelled cases, not universal safety or reliability.

## Scope, plan, and evidence

This folder already contains `discovery.json`, `assurance-scope.json`, and
`risk-plan.json`. The run command automatically uses them to make the local
Assurance Graph. The plan expects these dimensions when the confirmed scope
supports them: {", ".join((plan or {}).get("required_dimensions", ["classification", "confidence"]))}.

Grounding, RAG, tool/trajectory, security detection, robustness, repeatability, judge agreement, and provider cost metrics require redacted telemetry from the application. Use the advanced `command_json_v2` adapter only when those local measurements are available. Missing evidence is reported as `NOT MEASURABLE`, never invented.

To capture supported OpenTelemetry JSON metadata locally, run this in a second
terminal before the evaluation, then configure the test application with the
printed loopback URL and token:

```powershell
esx-eval telemetry --out .\out\telemetry.jsonl
```

For a browser journey, install the optional local dependency once:

```powershell
py -m pip install "exposurescopex-eval-runner[browser]"
playwright install chromium
```
{staging_note}'''


def serve_setup(default_directory: str | None = None) -> None:
    """Serve one local page on loopback until the user presses Ctrl+C."""
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/":
                self.send_error(404)
                return
            body = _guided_setup_html(token, default_directory).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.headers.get("X-ESX-Setup-Token") != token:
                self._json(403, {"error": "Local setup authorization failed"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 65_536:
                    raise ValueError("Request must contain at most 64 KB of JSON")
                values = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(values, dict):
                    raise ValueError("Request must be a JSON object")
                if self.path == "/api/discover":
                    self._json(200, discover_repository(values.get("repository", "")))
                    return
                if self.path == "/api/create-plan":
                    path, config = create_guided_plan(values)
                    self._json(201, {"config": str(path), "cases": len(config["dataset"]["cases"]), "profile": config["plan"]["profile"], "files": ["esx-eval.json", "discovery.json", "assurance-scope.json", "risk-plan.json", "README.md"], "planned_dimensions": config["assurance"]["planned_dimensions"]})
                    return
                self._json(404, {"error": "Unknown local setup endpoint"})
            except (ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Open the local setup page: {url}")
    print("The page is local-only. Press Ctrl+C here when you are finished.")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nLocal setup page stopped.")
    finally:
        server.server_close()


def _guided_setup_html(token: str, default_directory: str | None) -> str:
    """Render one local workflow without asking customers to write an adapter."""
    return """<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ESX Local Evaluation Setup</title><style>*{box-sizing:border-box}body{margin:0;background:#e9ece2;color:#182726;font:16px Georgia,serif}main{max-width:960px;margin:28px auto;padding:30px;background:#fffdf7;border:1px solid #19312e;box-shadow:7px 7px #19312e}h1{margin:0;font-size:40px}.lead{font-size:18px;color:#536a63}.step{border-top:1px solid #b8c7bf;padding:21px 0}h2{margin:0 0 8px}label{display:block;margin:13px 0 5px;font:13px ui-monospace,monospace}input,select,textarea{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:14px ui-monospace,monospace}textarea{min-height:95px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.scope{background:#f0f5ed;padding:12px;max-height:250px;overflow:auto}.scope label,.check{font:14px Georgia,serif}.scope input,.check input{width:auto;margin-right:8px}.note,.success{padding:12px;background:#f0f5ed;border-left:4px solid #507765}.success{background:#e6f3e7;border-color:#145c38}.hidden{display:none}button{margin-top:15px;background:#ef633d;color:white;border:2px solid #182726;padding:11px 16px;font-weight:bold;box-shadow:3px 3px #182726;cursor:pointer}button.secondary{background:#dfe9e2;color:#182726}pre{white-space:pre-wrap;word-break:break-word;background:#182726;color:#e7f1eb;padding:14px}@media(max-width:650px){main{margin:0;padding:20px;box-shadow:none;border:0}.grid{grid-template-columns:1fr}h1{font-size:32px}}</style></head><body><main><p style=\"font-family:monospace;color:#507765\">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up a real application evaluation</h1><p class=\"lead\">Choose one customer-facing workflow. You do not need to find or call every internal agent, and the runner never silently executes discovered code.</p><section class=\"step\"><h2>1. Discover and approve scope</h2><p>Optional: scan a local repository for routes, agents, RAG, tools, and observability. Source text stays on this computer.</p><label>APPLICATION REPOSITORY</label><input id=\"repository\" placeholder=\"C:\\\\work\\\\my-ai-app\"><button class=\"secondary\" onclick=\"discover()\">SCAN LOCALLY</button><div id=\"scope\" class=\"scope\">No repository scanned. The plan will contain one customer-declared workflow.</div></section><section class=\"step\"><h2>2. Connect the approved workflow</h2><p class=\"note\">Use an existing local JSON API whenever possible. Use a browser journey only for a local UI without an API. An adapter is not required for either path.</p><label>CONNECTION METHOD</label><select id=\"connection_type\" onchange=\"connectionChanged()\"><option value=\"http\">Existing local JSON API</option><option value=\"browser\">Local browser journey</option></select><div class=\"grid\"><div><label id=\"url_label\">LOCAL API URL</label><input id=\"url\" value=\"http://127.0.0.1:8000/evaluate\"></div><div><label>APPLICATION ID</label><input id=\"agent_id\" value=\"my-ai-application\"></div><div><label>VERSION UNDER TEST</label><input id=\"subject_version\" value=\"0.1.0\"></div><div><label>PROJECT KEY</label><input id=\"project_key\" value=\"default\"></div></div><div id=\"http_fields\" class=\"grid\"><div><label>LABEL RESPONSE PATH</label><input id=\"label_path\" value=\"decision.label\"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id=\"confidence_path\" value=\"decision.confidence\"></div></div><div id=\"browser_fields\" class=\"grid hidden\"><div><label>START PATH</label><input id=\"browser_path\" value=\"/\"></div><div><label>EXPECTED VISIBLE TEXT</label><input id=\"browser_expected_text\" placeholder=\"For example: Welcome\"></div></div><label id=\"remote_check\" class=\"check\"><input id=\"allow_remote\" type=\"checkbox\"> This is an approved staging API with mTLS and signed test-tenant attestation</label></section><section class=\"step\"><h2>3. Choose coverage and create the plan</h2><p>Profiles add safe baseline cases. Add product-specific cases if needed; all cases remain editable in the generated configuration.</p><label>EVALUATION PROFILE</label><select id=\"profile\"><option value=\"smoke\">Smoke check: 4 connection and boundary cases</option><option value=\"release\">Release readiness: 12 broader baseline cases</option><option value=\"red_team\">Adversarial safety review: 12 authorized boundary cases</option><option value=\"custom\">Custom: one editable starter case</option></select><label>OPTIONAL EXTRA CASES (JSON ARRAY, HTTP ONLY)</label><textarea id=\"custom_cases\" placeholder='[{\"case_id\":\"billing-001\",\"input\":{\"message\":\"Where is my invoice?\"},\"expected_label\":\"safe\"}]'></textarea><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id=\"directory\" value=\"__DIRECTORY__\"><label class=\"check\"><input id=\"confirm_plan\" type=\"checkbox\"> I reviewed the selected scope and understand missing evidence is reported as NOT MEASURABLE.</label><button onclick=\"createPlan()\">CREATE LOCAL EVALUATION</button><pre id=\"result\">This generates esx-eval.json, discovery.json, assurance-scope.json, risk-plan.json, and README.md.</pre></section><section class=\"step\"><h2>4. Run and inspect results</h2><pre>cd &lt;your-plan-folder&gt;\nesx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\nesx-eval view --report .\\out\\evaluation.local-report.html</pre><p>One command includes the generated scope and risk plan in the Assurance Graph. Prompts, outputs, source code, and results remain local.</p></section></main><script>const token=__TOKEN__;let latestDiscovery=null;const byId=id=>document.getElementById(id);async function post(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-ESX-Setup-Token':token},body:JSON.stringify(data)});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p}function showScope(data){const holder=byId('scope');holder.replaceChildren();const components=data.components||[];if(!components.length){holder.textContent='No integration hints found. The plan will contain one customer-declared workflow.';return}const heading=document.createElement('strong');heading.textContent='Confirm only the components safe to test:';holder.append(heading);components.forEach((item,index)=>{const label=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.checked=index===0;box.dataset.component=item.id;label.append(box,document.createTextNode(' '+item.name+' ('+item.kind+')'));holder.append(label)})}async function discover(){const holder=byId('scope');holder.textContent='Scanning locally...';try{latestDiscovery=await post('/api/discover',{repository:byId('repository').value});showScope(latestDiscovery)}catch(error){latestDiscovery=null;holder.textContent='Could not scan: '+error.message}}function connectionChanged(){const browser=byId('connection_type').value==='browser';byId('http_fields').classList.toggle('hidden',browser);byId('browser_fields').classList.toggle('hidden',!browser);byId('remote_check').classList.toggle('hidden',browser);byId('url_label').textContent=browser?'LOCAL WEB APP URL':'LOCAL API URL'}function selectedComponents(){return [...document.querySelectorAll('[data-component]:checked')].map(item=>item.dataset.component)}async function createPlan(){const out=byId('result');out.className='';out.textContent='Creating the reviewed local evaluation...';try{let extra=[];if(byId('custom_cases').value.trim()){extra=JSON.parse(byId('custom_cases').value);if(!Array.isArray(extra))throw Error('Extra cases must be a JSON array')}const payload={directory:byId('directory').value,agent_id:byId('agent_id').value,subject_version:byId('subject_version').value,project_key:byId('project_key').value,url:byId('url').value,connection_type:byId('connection_type').value,profile:byId('profile').value,custom_cases:extra,confirm_plan:byId('confirm_plan').checked,allow_remote:byId('allow_remote').checked,response_label_path:byId('label_path').value,response_confidence_path:byId('confidence_path').value,browser_path:byId('browser_path').value,browser_expected_text:byId('browser_expected_text').value};if(latestDiscovery){payload.discovery=latestDiscovery;payload.selected_component_ids=selectedComponents()}const created=await post('/api/create-plan',payload);out.className='success';out.textContent='Created '+created.config+'\\n\\nFiles: '+created.files.join(', ')+'\\nPlanned coverage: '+created.planned_dimensions.join(', ')+'\\n\\nNext: read README.md, review esx-eval.json, then run step 4.'}catch(error){out.textContent='Could not create plan: '+error.message}}</script></body></html>""".replace("__TOKEN__", json.dumps(token)).replace("__DIRECTORY__", json.dumps(default_directory or str(Path.cwd() / "esx-evaluation")))


def _setup_html(token: str, default_directory: str | None) -> str:
    directory = json.dumps(default_directory or str(Path.cwd() / "esx-evaluation"))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESX Local Evaluation Setup</title><style>*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(120deg,#e9ece2,#d4e6dc);color:#182726;font:16px Georgia,serif}}main{{max-width:1050px;margin:35px auto;padding:34px;background:#fffdf7;border:1px solid #19312e;box-shadow:8px 8px 0 #19312e}}h1{{font-size:42px;margin:0}}.lead{{color:#536a63;font-size:18px;max-width:760px}}.step{{border-top:1px solid #b8c7bf;padding:20px 0}}h2{{font-size:23px;margin:0 0 8px}}label{{display:block;font:13px ui-monospace,monospace;margin:14px 0 5px}}input,select{{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:15px ui-monospace,monospace}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:15px}}button{{margin-top:18px;background:#ef633d;color:white;border:2px solid #182726;padding:12px 18px;font:bold 16px ui-monospace,monospace;box-shadow:3px 3px 0 #182726;cursor:pointer}}button.secondary{{background:#dfe9e2;color:#182726}}pre{{background:#182726;color:#e7f1eb;padding:16px;white-space:pre-wrap;word-break:break-word}}.note{{background:#f0f5ed;border-left:4px solid #507765;padding:12px}}@media(max-width:650px){{main{{margin:0;padding:20px;box-shadow:none;border:0}}h1{{font-size:32px}}.grid{{grid-template-columns:1fr}}}}</style></head><body><main><p style="font-family:ui-monospace,monospace;color:#507765">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up a pre-release evaluation</h1><p class="lead">Connect the workflow your users actually use. For a normal web application, point us at its local JSON API. You do not need to locate or call each internal agent.</p><section class="step"><h2>1. Discover integration hints (optional)</h2><p>Scan a local repository for frameworks, routes, and observability signals. Source content stays on this computer.</p><label>APPLICATION REPOSITORY</label><input id="repository" placeholder="C:\\work\\my-ai-app"><button class="secondary" onclick="discover()">SCAN LOCALLY</button><pre id="discovery">No repository scanned yet.</pre></section><section class="step"><h2>2. Connect one user-facing workflow</h2><p class="note">Available now: JSON-over-HTTP endpoint. The runner sends one POST per case. Browser journeys and opaque custom protocols need their own connector; they are not silently guessed.</p><div class="grid"><div><label>LOCAL OR APPROVED STAGING URL</label><input id="url" value="http://127.0.0.1:8000/evaluate"></div><div><label>APPLICATION ID</label><input id="agent_id" value="my-ai-application"></div><div><label>VERSION UNDER TEST</label><input id="subject_version" value="0.1.0"></div><div><label>PROJECT KEY</label><input id="project_key" value="default"></div><div><label>LABEL RESPONSE PATH</label><input id="label_path" value="decision.label"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id="confidence_path" value="decision.confidence"></div></div><label><input id="allow_remote" type="checkbox" style="width:auto"> This is an approved non-local staging target</label></section><section class="step"><h2>3. Choose and review a plan</h2><p>Every plan is editable after creation. “Safe” means the request should be allowed; “unsafe” means the application should block or refuse it.</p><label>EVALUATION PROFILE</label><select id="profile"><option value="smoke">Smoke check: 4 connection and basic boundary cases</option><option value="release">Release readiness: 12 broader baseline cases</option><option value="red_team">Adversarial safety review: 12 authorized boundary cases</option><option value="custom">Custom: start empty and write cases yourself</option></select><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id="directory" value={directory}><button onclick="createPlan()">CREATE LOCAL PLAN</button><pre id="result">Review the generated esx-eval.json before running it.</pre></section><section class="step"><h2>4. Run and view your local results</h2><pre>cd &lt;your-plan-folder&gt;\nesx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\nesx-eval view --report .\\out\\evaluation.local-report.html</pre><p>Scores, raw responses, test prompts, and reports remain local unless your team separately opts into the signed upload flow.</p></section></main><script>const token={json.dumps(token)};async function post(path,data){{const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json','X-ESX-Setup-Token':token}},body:JSON.stringify(data)}});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p;}}async function discover(){{const out=document.querySelector('#discovery');out.textContent='Scanning locally...';try{{out.textContent=JSON.stringify(await post('/api/discover',{{repository:repository.value}}),null,2)}}catch(e){{out.textContent='Could not scan: '+e.message}}}}async function createPlan(){{const out=document.querySelector('#result');out.textContent='Creating local plan...';try{{let p={{profile:profile.value,response_label_path:label_path.value,response_confidence_path:confidence_path.value,request_mode:'message',allow_remote:allow_remote.checked}};['directory','agent_id','subject_version','project_key','url'].forEach(k=>p[k]=document.querySelector('#'+k).value);out.textContent=JSON.stringify(await post('/api/create-plan',p),null,2)+'\\n\\nNext: open esx-eval.json, review the labelled cases, then run the command below.'}}catch(e){{out.textContent='Could not create plan: '+e.message}}}}</script></body></html>'''
