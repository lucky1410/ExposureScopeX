# Approved Local Browser Workflows

Use browser journeys when a local application has no usable evaluation API.
They run only on a loopback HTTP(S) origin and never bypass authentication.

## Set up an approved login

1. Create a dedicated, least-privilege test account in a safe local or test environment.
2. Set its values in the shell that will run `esx-eval`; never place them in `esx-eval.json`.
3. In the local setup page, choose **Local browser workflow** and enable **Approved login**.
4. Enter the login path, post-login path, selectors, and stable post-login text.
5. Review the generated pre-auth and authenticated cases before running them.

Windows PowerShell:

```powershell
$env:ESX_TEST_USERNAME = "test-user@example.test"
$env:ESX_TEST_PASSWORD = "<test-account-password>"
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
```

macOS/Linux:

```bash
export ESX_TEST_USERNAME='test-user@example.test'
export ESX_TEST_PASSWORD='<test-account-password>'
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
```

The generated plan persists its session at `.esx/auth-session.json`. It may
contain cookies and local storage, so it stays beside the local plan with
restricted permissions where supported. Delete it when the account, role, or
environment changes.

## Use SSO or an approved existing session

Choose **Interactive SSO or existing approved browser session** in the setup
page when the application redirects to an identity provider or the tester must
approve the login themselves. No username, password, identity-provider cookie,
or application change is required.

1. Create the browser plan with an approved login path, post-login path, and stable post-login text.
2. Run `esx-eval browser-auth --config ./esx-eval.json`.
3. Complete the approved login in the visible browser window.
4. Return to the local application and press Enter in the terminal.
5. Run `esx-eval run --config ./esx-eval.json --out ./out/evaluation.json`.

The bootstrap verifies that the browser has returned to the approved local
application before saving the session. It keeps only that application's
cookies and local storage; identity-provider state is discarded. Re-run the
bootstrap whenever the saved session expires or the test account changes.

Check a saved session before a larger suite:

```text
esx-eval browser-session --config ./esx-eval.json --persona analyst
```

`session_usable` means the approved login route reached the configured local
post-login signal. `reauthentication_required` means the runner did not treat
the session as valid; bootstrap that persona again before running protected
workflows.

## Record a workflow instead of hand-writing JSON

Use the local recorder to turn one approved, authenticated browser journey
into a review-required case. It records only stable control selectors when
available. It never records typed values, pressed keys, page text, cookies,
local storage, credentials, or identity-provider state.

```text
esx-eval browser-record --config ./esx-eval.json --out ./investigations-recording.json --case-id investigations-queue --start-path /investigations --expected-text "Investigations queue"
esx-eval preflight --config ./esx-eval.json
```

Add `--add` only after reviewing `investigations-recording.json`. The resulting
case is still explicit scope: recording a journey does not authorize another
route, infer business intent, or turn discovery into coverage.

The preflight command runs without opening the application. It warns about
duplicate case IDs, repeated success signals, short or non-exact text matches,
missing assertions, and protected workflows that have no session setup. Fix a
warning before relying on a browser signal-match result.

## Add role-based workflow coverage

After repository discovery, `workflow-packs.json` contains review-required
candidates grouped by capability area. The suggestions are based only on
implemented literal routes; they do not assert that a route is user-facing,
reachable, or functionally correct.

1. List the reviewed candidates: `esx-eval workflow-pack list --config ./esx-eval.json`.
2. Add each required role as an isolated local session profile:

```text
esx-eval persona add --config ./esx-eval.json --id analyst --role analyst --login-path /login --success-text "Investigations"
esx-eval browser-auth --config ./esx-eval.json --persona analyst
```

3. Add a candidate only after choosing a stable, non-sensitive success signal:

```text
esx-eval workflow-pack add --config ./esx-eval.json --pack workflow-get-cases --persona analyst --expected-text "Investigations"
```

The command creates an explicit authenticated case with a capability area,
persona, path assertion, and retry-aware SPA waits. It does not run until the
normal `esx-eval run` command is invoked. Use `--no-authenticated` only for a
deliberately public workflow.

To reuse a reviewed pack across local plans, export it and apply it to another
browser plan that has the matching approved personas:

```text
esx-eval workflow-pack save --config ./esx-eval.json --name "VINI analyst journeys" --out ./vini-analyst-pack.json
esx-eval workflow-pack apply --config ./another-plan/esx-eval.json --pack-file ./vini-analyst-pack.json
```

Each applied case must still be reviewed for the recipient's paths, expected
signals, scope, test tenant, and authorization before it is run.

## Journey actions

| Action | Use |
| --- | --- |
| `goto` | Open an approved same-origin path. |
| `fill`, `click`, `press` | Interact with a known UI control. |
| `wait_for_url` | Wait for an exact same-origin redirect target. |
| `wait_for_text` | Wait for stable expected text after async work. |
| `wait_for_selector` | Wait for a selector state such as `visible`. |
| `wait_for_navigation` | Wait for the document loading state after a transition. |
| `wait_for_stable` | Allow a short bounded UI settle; pair it with a specific assertion. |
| `assert_path`, `assert_title` | Verify the rendered location or title. |
| `expect_text`, `expect_visible` | Compatibility aliases for visible text or selector checks. |

Each navigation, wait, and assertion can use `retry_count` from `0` to `5`
and `retry_delay_ms` from `0` to `5000`. ESX rejects retries on `click`,
`fill`, and `press` actions so a delayed interface cannot accidentally repeat
a state-changing operation.

Use explicit waits after sign-in or SPA actions. Do not use a generic network
idle wait as proof of readiness: telemetry and WebSockets can keep a healthy
app busy indefinitely.

## Coverage and diagnostics

The local report separates:

- **Discovered**: source and dependency evidence from the repository.
- **Approved**: components the user included in the evaluation scope.
- **Requested**: cases the reviewed plan asked ESX to run.
- **Executed**: browser cases that actually reached a workflow.
- **Blocked at session setup**: authenticated cases that could not begin because
  an approved session was unavailable. These are coverage limitations, not
  application failures, and they do not affect quality scores.
- **Assertion review**: executed workflow cases whose approved expected signal
  did not match. This is evidence to review, not an independently confirmed
  application defect.
- **Browser-only smoke summary**: a plain-language statement of whether an
  approved session was available, a declared page was reached, its visible
  signal matched, or the signal needs refinement. It is not an AI-quality
  score.
- **Measured**: dimensions backed by validated local evidence.

On a browser outcome, the report records the case ID, persona, capability area,
execution stage, failed action or session reason, completed/attempted step
counts, approved-origin status, document-ready state, and aggregate
console/page/request failure counts. It never records browser text, entered
values, credentials, cookies, or local storage. To retain a local image of the
failure state, enable `capture_failure_screenshots`; these files are not added
to the evaluation package or report.

When a workflow fails, PRE-D also lists up to three local `data-testid` or `id`
selector candidates found on the page. They are hints only: review them to
ensure they represent the intended user-visible state before replacing an
assertion. No page text is collected for this guidance.
