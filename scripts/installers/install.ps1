[CmdletBinding()]
param(
  [ValidatePattern('^[A-Za-z0-9._-]+$')]
  [string]$Profile = 'desktop',
  [string]$DshCommand = '',
  [string]$DshHome = '',
  # Used by the double-click launcher; never prompts during a dry run.
  [switch]$PromptForDshPath,
  # Only print the plan; change nothing.
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$bundleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$sourcePlugin = Join-Path $bundleRoot 'plugin'
$sourcePrompt = Join-Path $bundleRoot 'prompt-custom.json'
$logPath = Join-Path $bundleRoot 'install.log'

function Write-Step([string]$message) {
  Write-Host ('[dsh-prompt-custom] ' + $message)
}

function Get-HarnessProcesses {
  return @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessName -like '*DeepSeek*Harness*' -or
    $_.ProcessName -like '*deepseek-harness*' -or
    ($_.Path -and $_.Path -like '*DeepSeek Harness*')
  })
}

# Resolve a literal CLI path or a Desktop install directory without executing it.
function Resolve-DshCandidate {
  param([string]$Path, [switch]$AllowCommandFile)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $candidate = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
  if (Test-Path -LiteralPath $candidate -PathType Container) {
    $root = $candidate
  } elseif (Test-Path -LiteralPath $candidate -PathType Leaf) {
    $root = Split-Path -Parent $candidate
    $extension = [IO.Path]::GetExtension($candidate)
    $name = [IO.Path]::GetFileNameWithoutExtension($candidate)
    if ($AllowCommandFile -and ($extension -in @('.cmd', '.bat', '.ps1') -or ($extension -eq '.exe' -and $name -eq 'dsh'))) {
      return (Get-Item -LiteralPath $candidate).FullName
    }
  } else {
    return $null
  }
  $cli = Join-Path $root 'resources\runtime\cli\bin\dsh.cmd'
  if (Test-Path -LiteralPath $cli -PathType Leaf) {
    return (Get-Item -LiteralPath $cli).FullName
  }
  return $null
}

function Get-HarnessInstallLocations {
  # Processes and registered locations work with custom drives and folder names.
  foreach ($process in @(Get-HarnessProcesses)) {
    if ($process.Path) { $process.Path }
  }
  foreach ($registryRoot in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )) {
    foreach ($entry in @(Get-ItemProperty -Path $registryRoot -ErrorAction SilentlyContinue)) {
      if ($entry.DisplayName -notmatch '(?i)deepseek[\s-]*harness') { continue }
      if ($entry.InstallLocation) { $entry.InstallLocation }
      if ($entry.DisplayIcon) {
        # DisplayIcon may be quoted and end in an icon index, e.g. "D:\Apps\Harness.exe",0.
        ([string]$entry.DisplayIcon -replace ',\s*-?\d+\s*$', '').Trim().Trim('"')
      }
    }
  }
  foreach ($registryRoot in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\*',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\*'
  )) {
    foreach ($entry in @(Get-ItemProperty -Path $registryRoot -ErrorAction SilentlyContinue)) {
      $appPath = [string]$entry.'(default)'
      if ($entry.PSChildName -match '(?i)deepseek[\s-]*harness' -or $appPath -match '(?i)deepseek[\s-]*harness') {
        if ($appPath) { $appPath }
      }
    }
  }
  # Read known shortcut locations only; do not recursively search users' drives.
  $shell = $null
  try {
    $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
    foreach ($folderName in @('Programs', 'CommonPrograms', 'DesktopDirectory', 'CommonDesktopDirectory')) {
      $shortcutRoot = [Environment]::GetFolderPath($folderName)
      if (-not $shortcutRoot -or -not (Test-Path -LiteralPath $shortcutRoot -PathType Container)) { continue }
      foreach ($shortcutFile in @(Get-ChildItem -LiteralPath $shortcutRoot -Filter '*harness*.lnk' -File -Recurse -ErrorAction SilentlyContinue)) {
        $shortcut = $null
        try {
          $shortcut = $shell.CreateShortcut($shortcutFile.FullName)
          if ($shortcut.TargetPath) { $shortcut.TargetPath }
        } catch { } finally {
          if ($shortcut -and [Runtime.InteropServices.Marshal]::IsComObject($shortcut)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
          }
        }
      }
    }
  } catch { } finally {
    if ($shell -and [Runtime.InteropServices.Marshal]::IsComObject($shell)) {
      [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
  }
  # Registered/shortcut locations take precedence over leftover default installs.
  foreach ($base in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not [string]::IsNullOrWhiteSpace($base)) {
      if ($base -eq $env:LOCALAPPDATA) { Join-Path $base 'Programs\DeepSeek Harness' }
      else { Join-Path $base 'DeepSeek Harness' }
    }
  }
}

function Find-DshExecutable {
  param([string]$Command = '')
  if (-not [string]::IsNullOrWhiteSpace($Command)) {
    $resolved = Resolve-DshCandidate -Path $Command -AllowCommandFile
    if ($resolved) { return $resolved }
    # An explicit path must not silently fall back to a different installation.
    if ($Command -match '[/\\:]') { return $null }
    $commandInfo = Get-Command -Name $Command -CommandType Application,ExternalScript -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($commandInfo) { return $commandInfo.Source }
    return $null
  }
  $seen = @{}
  foreach ($location in @(Get-HarnessInstallLocations)) {
    if ([string]::IsNullOrWhiteSpace($location) -or $seen.ContainsKey($location)) { continue }
    $seen[$location] = $true
    $resolved = Resolve-DshCandidate -Path $location
    if ($resolved) { return $resolved }
  }
  $commandInfo = Get-Command -Name 'dsh' -CommandType Application,ExternalScript -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($commandInfo) { return $commandInfo.Source }
  return $null
}

if (-not (Test-Path -LiteralPath $sourcePlugin -PathType Container)) {
  throw 'The bundled plugin directory is missing.'
}

if ([string]::IsNullOrWhiteSpace($DshHome)) {
  if ([string]::IsNullOrWhiteSpace($env:DSH_HOME)) {
    $targetHome = Join-Path $env:USERPROFILE '.dsh'
  } else {
    $targetHome = $env:DSH_HOME.Trim()
  }
} else {
  $targetHome = $DshHome.Trim()
}
$targetHome = [System.IO.Path]::GetFullPath($targetHome)
$env:DSH_HOME = $targetHome

$dshExecutable = Find-DshExecutable -Command $DshCommand
if (-not $dshExecutable -and $PromptForDshPath -and -not $DryRun -and [string]::IsNullOrWhiteSpace($DshCommand)) {
  Write-Step 'DeepSeek Harness was not found automatically. Right-click its shortcut, choose Open file location, and copy the install folder path.'
  Write-Step 'Enter the install folder, or the full path to DeepSeek Harness.exe or dsh.cmd; press Enter to cancel.'
  $enteredPath = Read-Host 'DeepSeek Harness path'
  if (-not [string]::IsNullOrWhiteSpace($enteredPath)) {
    $dshExecutable = Find-DshExecutable -Command $enteredPath
  }
}
if (-not $dshExecutable) {
  throw 'DSH command-line tool not found. Run .\scripts\installers\install.ps1 -DshCommand "D:\App\DeepSeek Harness" (replace with the real install directory or the dsh.cmd path). If the data directory was moved too, also pass -DshHome "D:\data\.dsh"; do not use the program install directory as the data directory.'
}

if ($Profile -eq 'desktop') {
  $desktopProfile = Join-Path $targetHome 'profiles\desktop'
  if (-not (Test-Path -LiteralPath (Join-Path $desktopProfile 'package.json') -PathType Leaf)) {
    throw ('Desktop profile not found: ' + $desktopProfile + '. Start DeepSeek Harness Desktop once first; if the data directory was moved, pass -DshHome to point at the .dsh data directory (not the program install directory).')
  }
}

$pluginTarget = Join-Path $targetHome 'local-plugins\dsh-prompt-custom'
$promptTarget = Join-Path $targetHome 'prompt-custom.json'
$harnessProcesses = Get-HarnessProcesses

if ($DryRun) {
  Write-Step 'Dry run; nothing will change.'
  Write-Step ('bundle    : ' + $bundleRoot)
  Write-Step ('plugin to : ' + $pluginTarget)
  Write-Step ('prompt to : ' + $promptTarget)
  Write-Step ('dsh cli   : ' + $dshExecutable)
  Write-Step ('harness   : ' + $(if ($harnessProcesses.Count) { 'running (' + $harnessProcesses.Count + ' processes)' } else { 'not running' }))
  return
}

# Still running: warn only, change nothing.
if ($harnessProcesses.Count -gt 0) {
  Write-Host ''
  Write-Step ('DeepSeek Harness is running (' + $harnessProcesses.Count + ' processes).')
  Write-Step 'Quit DeepSeek Harness completely first (including the tray icon at the bottom right, then Quit), then double-click run-installer.cmd again.'
  Write-Step 'No files were changed this time.'
  Write-Host ''
  exit 1
}

$promptBackup = $null
$hadPrompt = Test-Path -LiteralPath $promptTarget -PathType Leaf
$sourceHash = if (Test-Path -LiteralPath $sourcePrompt -PathType Leaf) { (Get-FileHash -LiteralPath $sourcePrompt -Algorithm SHA256).Hash } else { '' }
$targetMatches = $false

if ($hadPrompt -and $sourceHash) {
  $targetHash = (Get-FileHash -LiteralPath $promptTarget -Algorithm SHA256).Hash
  $targetMatches = $sourceHash -eq $targetHash
  if (-not $targetMatches) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $promptBackup = $promptTarget + '.backup-' + $stamp
    [System.IO.File]::Copy($promptTarget, $promptBackup, $false)
    Write-Step ('Existing prompt configuration backed up to: ' + $promptBackup)
  }
}

New-Item -ItemType Directory -Force -Path $pluginTarget | Out-Null
Get-ChildItem -LiteralPath $sourcePlugin -Force | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination $pluginTarget -Recurse -Force
}
if ($sourceHash -and -not $targetMatches) {
  [System.IO.File]::Copy($sourcePrompt, $promptTarget, $true)
}
Write-Step ('Files copied to ' + $pluginTarget)

try {
  & $dshExecutable plugin --profile $Profile add $pluginTarget
  $installExitCode = $LASTEXITCODE
  if ($installExitCode -ne 0) {
    throw "DSH plugin installation failed with exit code $installExitCode."
  }
} catch {
  if ($hadPrompt -and $promptBackup -and (Test-Path -LiteralPath $promptBackup -PathType Leaf)) {
    [System.IO.File]::Copy($promptBackup, $promptTarget, $true)
    Write-Step 'Install failed; the original prompt configuration was restored'
  }
  throw
}

$version = ''
try { $version = (Get-Content -LiteralPath (Join-Path $sourcePlugin 'package.json') -Raw | ConvertFrom-Json).version } catch { }
Write-Step ('Install complete: @deepseek-ai/dsh-prompt-custom ' + $version + ' (profile: ' + $Profile + '）')
try {
  Add-Content -LiteralPath $logPath -Value ((Get-Date -Format o) + ' installed version ' + $version) -Encoding UTF8
} catch { }

Write-Step 'Start DeepSeek Harness now to load the new version.'
