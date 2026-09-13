"""Local setup page for the customer-facing HTTP evaluation workflow."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import webbrowser
from typing import Any

from .discovery import discover_repository
from .profiles import PROFILE_NAMES, build_cases, profile
from .runner import CONFIG_SCHEMA_VERSION


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,62}$")


def create_http_plan(values: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Create an editable plan for a standard JSON HTTP application."""
    for key in ("directory", "agent_id", "subject_version", "project_key", "url"):
        if not isinstance(values.get(key), str) or not values[key].strip():
            raise ValueError(f"{key.replace('_', ' ')} is required")
    if not _IDENTIFIER.fullmatch(values["agent_id"]) or not _IDENTIFIER.fullmatch(values["project_key"]):
        raise ValueError("Application ID and project key must use lowercase letters, digits, and hyphens")
    profile_name = values.get("profile", "smoke")
    if profile_name not in PROFILE_NAMES:
        raise ValueError("Choose a valid evaluation profile")
    cases = build_cases(profile_name)
    target = Path(values["directory"]).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        raise ValueError(f"Refusing to overwrite non-empty folder: {target}")
    dataset_version = f"{values['agent_id']}-{profile_name}-1.0"
    config = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "evaluation": {"name": f"{values['agent_id']} {profile(profile_name)['name'].lower()}", "agent_id": values["agent_id"], "subject_version": values["subject_version"], "subject_type": values.get("subject_type", "agent"), "project_key": values["project_key"], "dataset_version": dataset_version, "required_dimensions": ["classification", "confidence"]},
        "dataset": {"version": dataset_version, "cases": cases},
        "adapter": {"type": "http_json_target", "url": values["url"], "request_mode": values.get("request_mode", "message"), "response_label_path": values.get("response_label_path", "decision.label"), "response_confidence_path": values.get("response_confidence_path", "decision.confidence"), "timeout_seconds": 60, "allow_remote": bool(values.get("allow_remote"))},
        "source": {"origin": "local"},
        "plan": {"profile": profile_name, "profile_description": profile(profile_name)["description"], "review_required": True},
    }
    target.mkdir(parents=True, exist_ok=True)
    path = target / "esx-eval.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (target / "README.md").write_text(_plan_readme(config), encoding="utf-8")
    return path, config


def _plan_readme(config: dict[str, Any]) -> str:
    adapter = config["adapter"]
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

## Advanced assurance metrics

Grounding, RAG, tool/trajectory, security detection, robustness, repeatability, judge agreement, and provider cost metrics require redacted telemetry from the application. Use the advanced `command_json_v2` adapter only when those local measurements are available. Missing evidence is reported as `NOT MEASURABLE`, never invented.
'''


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
            body = _setup_html(token, default_directory).encode("utf-8")
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
                    path, config = create_http_plan(values)
                    self._json(201, {"config": str(path), "cases": len(config["dataset"]["cases"]), "profile": config["plan"]["profile"]})
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


def _setup_html(token: str, default_directory: str | None) -> str:
    directory = json.dumps(default_directory or str(Path.cwd() / "esx-evaluation"))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESX Local Evaluation Setup</title><style>*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(120deg,#e9ece2,#d4e6dc);color:#182726;font:16px Georgia,serif}}main{{max-width:1050px;margin:35px auto;padding:34px;background:#fffdf7;border:1px solid #19312e;box-shadow:8px 8px 0 #19312e}}h1{{font-size:42px;margin:0}}.lead{{color:#536a63;font-size:18px;max-width:760px}}.step{{border-top:1px solid #b8c7bf;padding:20px 0}}h2{{font-size:23px;margin:0 0 8px}}label{{display:block;font:13px ui-monospace,monospace;margin:14px 0 5px}}input,select{{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:15px ui-monospace,monospace}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:15px}}button{{margin-top:18px;background:#ef633d;color:white;border:2px solid #182726;padding:12px 18px;font:bold 16px ui-monospace,monospace;box-shadow:3px 3px 0 #182726;cursor:pointer}}button.secondary{{background:#dfe9e2;color:#182726}}pre{{background:#182726;color:#e7f1eb;padding:16px;white-space:pre-wrap;word-break:break-word}}.note{{background:#f0f5ed;border-left:4px solid #507765;padding:12px}}@media(max-width:650px){{main{{margin:0;padding:20px;box-shadow:none;border:0}}h1{{font-size:32px}}.grid{{grid-template-columns:1fr}}}}</style></head><body><main><p style="font-family:ui-monospace,monospace;color:#507765">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up a pre-release evaluation</h1><p class="lead">Connect the workflow your users actually use. For a normal web application, point us at its local JSON API. You do not need to locate or call each internal agent.</p><section class="step"><h2>1. Discover integration hints (optional)</h2><p>Scan a local repository for frameworks, routes, and observability signals. Source content stays on this computer.</p><label>APPLICATION REPOSITORY</label><input id="repository" placeholder="C:\\work\\my-ai-app"><button class="secondary" onclick="discover()">SCAN LOCALLY</button><pre id="discovery">No repository scanned yet.</pre></section><section class="step"><h2>2. Connect one user-facing workflow</h2><p class="note">Available now: JSON-over-HTTP endpoint. The runner sends one POST per case. Browser journeys and opaque custom protocols need their own connector; they are not silently guessed.</p><div class="grid"><div><label>LOCAL OR APPROVED STAGING URL</label><input id="url" value="http://127.0.0.1:8000/evaluate"></div><div><label>APPLICATION ID</label><input id="agent_id" value="my-ai-application"></div><div><label>VERSION UNDER TEST</label><input id="subject_version" value="0.1.0"></div><div><label>PROJECT KEY</label><input id="project_key" value="default"></div><div><label>LABEL RESPONSE PATH</label><input id="label_path" value="decision.label"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id="confidence_path" value="decision.confidence"></div></div><label><input id="allow_remote" type="checkbox" style="width:auto"> This is an approved non-local staging target</label></section><section class="step"><h2>3. Choose and review a plan</h2><p>Every plan is editable after creation. “Safe” means the request should be allowed; “unsafe” means the application should block or refuse it.</p><label>EVALUATION PROFILE</label><select id="profile"><option value="smoke">Smoke check: 4 connection and basic boundary cases</option><option value="release">Release readiness: 12 broader baseline cases</option><option value="red_team">Adversarial safety review: 12 authorized boundary cases</option><option value="custom">Custom: start empty and write cases yourself</option></select><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id="directory" value={directory}><button onclick="createPlan()">CREATE LOCAL PLAN</button><pre id="result">Review the generated esx-eval.json before running it.</pre></section><section class="step"><h2>4. Run and view your local results</h2><pre>cd &lt;your-plan-folder&gt;\nesx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\nesx-eval view --report .\\out\\evaluation.local-report.html</pre><p>Scores, raw responses, test prompts, and reports remain local unless your team separately opts into the signed upload flow.</p></section></main><script>const token={json.dumps(token)};async function post(path,data){{const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json','X-ESX-Setup-Token':token}},body:JSON.stringify(data)}});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p;}}async function discover(){{const out=document.querySelector('#discovery');out.textContent='Scanning locally...';try{{out.textContent=JSON.stringify(await post('/api/discover',{{repository:repository.value}}),null,2)}}catch(e){{out.textContent='Could not scan: '+e.message}}}}async function createPlan(){{const out=document.querySelector('#result');out.textContent='Creating local plan...';try{{let p={{profile:profile.value,response_label_path:label_path.value,response_confidence_path:confidence_path.value,request_mode:'message',allow_remote:allow_remote.checked}};['directory','agent_id','subject_version','project_key','url'].forEach(k=>p[k]=document.querySelector('#'+k).value);out.textContent=JSON.stringify(await post('/api/create-plan',p),null,2)+'\\n\\nNext: open esx-eval.json, review the labelled cases, then run the command below.'}}catch(e){{out.textContent='Could not create plan: '+e.message}}}}</script></body></html>'''
