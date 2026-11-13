[CmdletBinding()]
param(
  [string]$Project = '',
  [string]$ConfigDir = '',
  [string]$Model = '',
  [switch]$DryRun,
  [switch]$WithTools
)

$ErrorActionPreference = 'Stop'
$node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue
if (-not $node) { throw 'Node.js 20 or newer is required. Install it, then run this installer again.' }
$installerArgs = @((Join-Path (Split-Path -Parent $PSScriptRoot) 'install.mjs'), 'opencode')
if ($Project) { $installerArgs += @('--project', $Project) }
if ($ConfigDir) { $installerArgs += @('--config-dir', $ConfigDir) }
if ($Model) { $installerArgs += @('--model', $Model) }
if ($DryRun) { $installerArgs += '--dry-run' }
if ($WithTools) { $installerArgs += '--with-tools' }
& $node.Source @installerArgs
if ($LASTEXITCODE -ne 0) { throw "OpenCode installation failed with exit code $LASTEXITCODE." }
