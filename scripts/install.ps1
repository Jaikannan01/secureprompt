<#
  SecurePrompt installer (Windows PowerShell)
  Usage:
    iwr -useb https://raw.githubusercontent.com/<org>/secureprompt/main/scripts/install.ps1 | iex
    $env:METHOD='git'; iwr -useb https://your.domain/install.ps1 | iex
#>

param(
  [string]$RepoUrl = $env:REPO_URL -or 'https://github.com/yourusername/secureprompt.git',
  [string]$Branch = $env:BRANCH -or 'main',
  [string]$Dir = $env:DIR,
  [ValidateSet('git','zip')]
  [string]$Method = $env:METHOD -or 'git',
  [switch]$SkipBuild
)

function Write-Info($msg){ Write-Host "==> $msg" -ForegroundColor Green }
function Write-Warn($msg){ Write-Host "==> $msg" -ForegroundColor Yellow }
function Write-Err($msg){ Write-Host "ERROR: $msg" -ForegroundColor Red }

if (-not $Dir) {
  $name = [System.IO.Path]::GetFileNameWithoutExtension($RepoUrl)
  $Dir = $name
}

Write-Info "Checking prerequisites"
foreach ($cmd in @('node','npm')) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Err "'$cmd' is required"; exit 1 }
}

Write-Info "Installing SecurePrompt ($Method)"
if (Test-Path $Dir) { Write-Warn "Target directory '$Dir' already exists" }
else {
  if ($Method -eq 'git') {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Err "'git' is required for METHOD=git"; exit 1 }
    git clone --depth=1 --branch $Branch $RepoUrl $Dir
  } else {
    if ($RepoUrl -match 'github.com/([^/]+/[^/.]+)') {
      $orgRepo = $Matches[1]
      $zipUrl = "https://codeload.github.com/$orgRepo/zip/refs/heads/$Branch"
      $tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name (New-Guid) -Force
      $zipPath = Join-Path $tmp 'src.zip'
      Invoke-WebRequest -UseBasicParsing -Uri $zipUrl -OutFile $zipPath
      Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
      $srcDir = Get-ChildItem $tmp -Directory | Where-Object { $_.Name -like "*-$Branch" } | Select-Object -First 1
      Move-Item $srcDir.FullName $Dir
      Remove-Item $tmp -Recurse -Force
    } else {
      Write-Err "Automatic ZIP download only supported for GitHub repos"; exit 1
    }
  }
}

Set-Location $Dir
Write-Info "Installing dependencies"
npm install

if (-not $SkipBuild) {
  Write-Info "Building workspaces"
  npm run build
} else {
  Write-Warn "Skipping build as requested"
}

Write-Info "Installation complete!"
Write-Host "`nTo use the library in your project:" -ForegroundColor Cyan
Write-Host "  npm install secureprompt"

