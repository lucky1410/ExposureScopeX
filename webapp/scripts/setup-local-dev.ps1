$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $repoRoot "backend"
$frontendDir = Join-Path $repoRoot "frontend"
$envFile = Join-Path $repoRoot ".env"
$envExample = Join-Path $repoRoot ".env.example"
$venvDir = Join-Path $backendDir ".venv"

function Resolve-Python {
    $candidates = @(
        (Join-Path $venvDir "Scripts\python.exe"),
        "python",
        "py"
    )

    foreach ($candidate in $candidates) {
        try {
            & $candidate --version *> $null
            return $candidate
        } catch {
        }
    }

    throw "Python 3 was not found. Install Python 3.12+ or update this script with the correct path."
}

if (-not (Test-Path $envFile)) {
    Copy-Item -LiteralPath $envExample -Destination $envFile
    Write-Host "Created webapp/.env from .env.example"
}

$python = Resolve-Python

if (-not (Test-Path $venvDir)) {
    & $python -m venv $venvDir
}

$venvPython = Join-Path $venvDir "Scripts\python.exe"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r (Join-Path $backendDir "requirements.txt")

if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Push-Location $frontendDir
    try {
        npm ci
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "Local dev setup is ready."
Write-Host "Backend:  $venvPython -m uvicorn app.main:app --reload --port 8001"
Write-Host "Frontend: cd `"$frontendDir`"; npm run dev"
