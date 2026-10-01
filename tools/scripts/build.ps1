$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
Push-Location apps\desktop
npm install --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
npm run build
if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }
Pop-Location
cargo build --release -p canto-app
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
Write-Host "Built: target\release\canto.exe"
