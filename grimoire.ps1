# grimoire.ps1 - install, update, uninstall or run (without installing) the tools in this repo.
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.ps1))) <command> <tool> [options]
#   powershell -ExecutionPolicy Bypass -File grimoire.ps1 <command> <tool> [options]
#
# Commands
#   install   <tool> [--system | --dir DIR] [--ref REF] [--force]
#   update    <tool|all> [--ref REF]
#   uninstall <tool|all> [--purge]          (alias: remove)
#   run       <tool> [tool arguments...]    download -> run -> delete everything
#   list
#
# Install locations (Windows)
#   local  (default)  %LOCALAPPDATA%\grimoires\<tool>  command in %LOCALAPPDATA%\grimoires\bin (added to user PATH)
#   system (--system) %ProgramFiles%\grimoires\<tool>  command in %ProgramFiles%\grimoires\bin (machine PATH, needs admin)
# On Linux/macOS (pwsh) the same layout as grimoire.sh is used.
#
# Environment: GRIMOIRE_REF (branch/tag, default main), GRIMOIRE_REPO (owner/repo).

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$GrimoireArgs = @($args)
$Repo = if ($env:GRIMOIRE_REPO) { $env:GRIMOIRE_REPO } else { 'Emp5r0R/grimoires' }
$DefaultRef = if ($env:GRIMOIRE_REF) { $env:GRIMOIRE_REF } else { 'main' }
$OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows
$LauncherTag = 'grimoire launcher'

# ---------------------------------------------------------------------------
# tool registry
# ---------------------------------------------------------------------------
$Tools = [ordered]@{
    'media-drop'  = @{ Dir = 'anon-media-uploader'; Entry = 'media_drop.py'; Req = 'requirements.txt'; Needs = @(); Cache = 'media-drop' }
    'email-guard' = @{ Dir = 'github-email-scanAndScrub'; Entry = 'github_email_guard.py'; Req = 'requirements.txt'; Needs = @('git'); Cache = $null }
}
$Aliases = @{ 'anon-media-uploader' = 'media-drop'; 'github-email-guard' = 'email-guard'; 'github-email-scanAndScrub' = 'email-guard' }

if ($OnWindows) {
    $LocalRoot = Join-Path $env:LOCALAPPDATA 'grimoires'
    $LocalBin = Join-Path $LocalRoot 'bin'
    $SystemRoot = Join-Path $env:ProgramFiles 'grimoires'
    $SystemBin = Join-Path $SystemRoot 'bin'
    $CacheRoot = Join-Path $HOME '.cache'
} else {
    $dataHome = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path $HOME '.local/share' }
    $LocalRoot = Join-Path $dataHome 'grimoires'
    $LocalBin = Join-Path $HOME '.local/bin'
    $SystemRoot = '/opt/grimoires'
    $SystemBin = '/usr/local/bin'
    $CacheRoot = if ($env:XDG_CACHE_HOME) { $env:XDG_CACHE_HOME } else { Join-Path $HOME '.cache' }
}

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
function Say([string]$m) { [Console]::Error.WriteLine("[*] $m") }
function Ok([string]$m) { [Console]::Error.WriteLine("[+] $m") }
function Warn([string]$m) { [Console]::Error.WriteLine("[!] $m") }
function Fail([string]$m) { throw "[x] $m" }

function Get-Tool([string]$name) {
    if ($Aliases.ContainsKey($name)) { $name = $Aliases[$name] }
    if (-not $name -or -not $Tools.Contains($name)) { Fail "unknown tool '$name' (tools: $($Tools.Keys -join ', '))" }
    $t = $Tools[$name].Clone()
    $t.Name = $name
    foreach ($c in $t.Needs) {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { Fail "'$c' is required but not installed" }
    }
    return $t
}

function Test-Admin {
    if ($OnWindows) {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    return ((& id -u) -eq '0')
}

function Find-Python {
    $candidates = @(@{ Exe = 'py'; Args = @('-3') }, @{ Exe = 'python3'; Args = @() }, @{ Exe = 'python'; Args = @() })
    foreach ($c in $candidates) {
        if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $v = & $c.Exe @($c.Args + @('-c', 'import sys; print(sys.version_info[0])')) 2>$null
            if ("$v".Trim() -eq '3') { return $c }
        } catch { }
    }
    Fail 'Python 3 is required (https://www.python.org/downloads/)'
}

function New-TempDir {
    $p = Join-Path ([IO.Path]::GetTempPath()) ("grimoire-" + [Guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Path $p -Force | Out-Null
    return $p
}

# Copies <repo>/<tool dir> to $dest\app and the helpers to $dest.
function Get-Source($tool, [string]$ref, [string]$dest) {
    $tmp = New-TempDir
    try {
        Say "downloading $Repo@$ref"
        $zip = Join-Path $tmp 'src.zip'
        Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/$Repo/zip/$ref" -OutFile $zip
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $root = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
        $src = Join-Path $root.FullName $tool.Dir
        if (-not (Test-Path $src)) { Fail "$($tool.Dir) not found in $Repo@$ref" }
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        $app = Join-Path $dest 'app'
        if (Test-Path $app) { Remove-Item $app -Recurse -Force }
        Copy-Item -Path $src -Destination $app -Recurse
        foreach ($h in @('grimoire.ps1', 'grimoire.sh')) {
            $hp = Join-Path $root.FullName $h
            if (Test-Path $hp) { Copy-Item $hp (Join-Path $dest $h) -Force }
        }
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-Python($tool, [string]$dest) {
    $py = Find-Python
    $venv = Join-Path $dest 'venv'
    & $py.Exe @($py.Args + @('-m', 'venv', $venv))
    if ($LASTEXITCODE -ne 0) { Fail 'could not create a virtualenv (python -m venv failed)' }
    $venvBin = if ($OnWindows) { Join-Path $venv 'Scripts' } else { Join-Path $venv 'bin' }
    $venvPy = if ($OnWindows) { Join-Path $venvBin 'python.exe' } else { Join-Path $venvBin 'python' }
    Say "installing python modules into $venv"
    & $venvPy -m pip install -q --disable-pip-version-check --upgrade pip 2>$null | Out-Null
    $req = Join-Path (Join-Path $dest 'app') $tool.Req
    if (Test-Path $req) {
        & $venvPy -m pip install -q --disable-pip-version-check --upgrade -r $req
        if ($LASTEXITCODE -ne 0) { Fail 'pip install failed' }
    }
    return @{ Py = $venvPy; VenvBin = $venvBin }
}

function Write-Launcher($tool, [string]$bin, [string]$dest, $env_) {
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $entry = Join-Path (Join-Path $dest 'app') $tool.Entry
    $helper = Join-Path $dest 'grimoire.ps1'
    if ($OnWindows) {
        $path = Join-Path $bin "$($tool.Name).cmd"
        $text = @"
@echo off
rem $LauncherTag for $($tool.Name) ($dest)
if /i "%~1"=="self-update" ( powershell -NoProfile -ExecutionPolicy Bypass -File "$helper" update $($tool.Name) & exit /b %errorlevel% )
if /i "%~1"=="self-uninstall" ( powershell -NoProfile -ExecutionPolicy Bypass -File "$helper" uninstall $($tool.Name) & exit /b %errorlevel% )
set "PATH=$($env_.VenvBin);%PATH%"
"$($env_.Py)" "$entry" %*
"@
        Set-Content -Path $path -Value $text -Encoding ASCII
    } else {
        $path = Join-Path $bin $tool.Name
        $text = @"
#!/bin/sh
# $LauncherTag for $($tool.Name) ($dest)
case "`${1:-}" in
  self-update) shift; exec pwsh -NoProfile -File "$helper" update $($tool.Name) "`$@" ;;
  self-uninstall|self-remove) shift; exec pwsh -NoProfile -File "$helper" uninstall $($tool.Name) "`$@" ;;
esac
PATH="$($env_.VenvBin):`$PATH"; export PATH
exec "$($env_.Py)" "$entry" "`$@"
"@
        Set-Content -Path $path -Value $text -Encoding ASCII
        & chmod 755 $path
    }
    return $path
}

function Add-ToPath([string]$bin, [string]$scope) {
    if (-not $OnWindows) {
        if (-not (($env:PATH -split ':') -contains $bin)) { Warn "$bin is not in your PATH; add it to your shell profile" }
        return
    }
    $target = if ($scope -eq 'system') { 'Machine' } else { 'User' }
    $current = [Environment]::GetEnvironmentVariable('Path', $target)
    $parts = @($current -split ';' | Where-Object { $_ })
    if ($parts -notcontains $bin) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $bin) -join ';'), $target)
        Say "added $bin to the $target PATH (open a new terminal to use it)"
    }
    if (-not (($env:Path -split ';') -contains $bin)) { $env:Path = "$env:Path;$bin" }
}

function Remove-FromPath([string]$bin, [string]$scope) {
    if (-not $OnWindows) { return }
    if ((Test-Path $bin) -and (Get-ChildItem $bin -ErrorAction SilentlyContinue)) { return }  # other tools still there
    $target = if ($scope -eq 'system') { 'Machine' } else { 'User' }
    $current = [Environment]::GetEnvironmentVariable('Path', $target)
    $parts = @($current -split ';' | Where-Object { $_ -and $_ -ne $bin })
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), $target)
    if (Test-Path $bin) { Remove-Item $bin -Force -Recurse -ErrorAction SilentlyContinue }
}

function Save-Meta([string]$dest, $meta) {
    $meta | ConvertTo-Json | Set-Content -Path (Join-Path $dest '.grimoire.json') -Encoding UTF8
}

function Find-Install($tool, [string]$customDir) {
    $dirs = @()
    if ($customDir) { $dirs += (Join-Path $customDir $tool.Name) }
    $dirs += (Join-Path $LocalRoot $tool.Name), (Join-Path $SystemRoot $tool.Name)
    foreach ($d in $dirs) {
        $m = Join-Path $d '.grimoire.json'
        if (Test-Path $m) { return @{ Dest = $d; Meta = (Get-Content $m -Raw | ConvertFrom-Json) } }
    }
    return $null
}

function Read-Options([string[]]$rest, [string[]]$withValue) {
    $o = @{}
    for ($i = 0; $i -lt $rest.Count; $i++) {
        $k = $rest[$i] -replace '^-+', ''
        if ($withValue -contains $k) {
            if ($i + 1 -ge $rest.Count) { Fail "--$k needs a value" }
            $o[$k] = $rest[$i + 1]; $i++
        } elseif ($k) { $o[$k] = $true }
    }
    return $o
}

# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
function Invoke-Install([string]$name, [string[]]$rest) {
    $tool = Get-Tool $name
    $o = Read-Options $rest @('dir', 'ref')
    foreach ($k in $o.Keys) { if (@('system', 'local', 'dir', 'ref', 'force') -notcontains $k) { Fail "unknown option --$k" } }
    $scope = 'local'; $root = $LocalRoot; $bin = $LocalBin
    if ($o.system) { $scope = 'system'; $root = $SystemRoot; $bin = $SystemBin }
    if ($o.dir) { $scope = 'custom'; $root = $o.dir; $bin = Join-Path $o.dir 'bin' }
    if ($scope -eq 'system' -and -not (Test-Admin)) { Fail 'system install needs an elevated (Administrator / root) shell' }
    $ref = if ($o.ref) { $o.ref } else { $DefaultRef }
    $dest = Join-Path $root $tool.Name
    if ((Test-Path (Join-Path $dest '.grimoire.json')) -and -not $o.force) {
        Fail "$($tool.Name) is already installed in $dest (use: update $($tool.Name), or install --force)"
    }
    Get-Source $tool $ref $dest
    $env_ = Initialize-Python $tool $dest
    $launcher = Write-Launcher $tool $bin $dest $env_
    Save-Meta $dest @{ tool = $tool.Name; ref = $ref; scope = $scope; bin = $bin; launcher = $launcher; python = $env_.Py; venv_bin = $env_.VenvBin; installed_at = (Get-Date).ToUniversalTime().ToString('s') + 'Z' }
    Add-ToPath $bin $scope
    Ok "installed $($tool.Name) -> $launcher  (files in $dest)"
}

function Invoke-Update([string]$name, [string[]]$rest) {
    $o = Read-Options $rest @('dir', 'ref')
    if ($name -eq 'all') {
        $found = $false
        foreach ($t in $Tools.Keys) {
            if (Find-Install (Get-Tool $t) $o.dir) { $found = $true; Invoke-Update $t $rest }
        }
        if (-not $found) { Warn 'nothing installed' }
        return
    }
    $tool = Get-Tool $name
    $inst = Find-Install $tool $o.dir
    if (-not $inst) { Fail "$($tool.Name) is not installed (use: install $($tool.Name))" }
    $m = $inst.Meta
    if ($m.scope -eq 'system' -and -not (Test-Admin)) { Fail 'updating a system install needs an elevated shell' }
    $ref = if ($o.ref) { $o.ref } else { $m.ref }
    Get-Source $tool $ref $inst.Dest
    $env_ = Initialize-Python $tool $inst.Dest
    $launcher = Write-Launcher $tool $m.bin $inst.Dest $env_
    Save-Meta $inst.Dest @{ tool = $tool.Name; ref = $ref; scope = $m.scope; bin = $m.bin; launcher = $launcher; python = $env_.Py; venv_bin = $env_.VenvBin; installed_at = (Get-Date).ToUniversalTime().ToString('s') + 'Z' }
    Ok "updated $($tool.Name) ($($inst.Dest), ref $ref)"
}

function Invoke-Uninstall([string]$name, [string[]]$rest) {
    $o = Read-Options $rest @('dir')
    if ($name -eq 'all') {
        foreach ($t in $Tools.Keys) { if (Find-Install (Get-Tool $t) $o.dir) { Invoke-Uninstall $t $rest } }
        return
    }
    $tool = Get-Tool $name
    $inst = Find-Install $tool $o.dir
    if (-not $inst) { Fail "$($tool.Name) is not installed" }
    $m = $inst.Meta
    if ($m.scope -eq 'system' -and -not (Test-Admin)) { Fail 'removing a system install needs an elevated shell' }
    if ($m.launcher -and (Test-Path $m.launcher) -and (Select-String -Path $m.launcher -Pattern $LauncherTag -Quiet)) {
        Remove-Item $m.launcher -Force
    }
    Remove-Item $inst.Dest -Recurse -Force
    Remove-FromPath $m.bin $m.scope
    $parent = Split-Path $inst.Dest -Parent
    if ((Test-Path $parent) -and -not (Get-ChildItem $parent -Force)) { Remove-Item $parent -Force }
    if ($o.purge -and $tool.Cache) {
        $cache = Join-Path $CacheRoot $tool.Cache
        if (Test-Path $cache) { Remove-Item $cache -Recurse -Force; Say "removed cache $cache" }
    }
    Ok "uninstalled $($tool.Name)"
}

function Invoke-Run([string]$name, [string[]]$rest) {
    $tool = Get-Tool $name
    $tmp = New-TempDir
    $saved = @{ PIP = $env:PIP_CACHE_DIR; XDG = $env:XDG_CACHE_HOME; PATH = $env:PATH }
    try {
        # keep pip's and the tool's caches inside the temp dir so nothing is left behind
        $env:PIP_CACHE_DIR = Join-Path $tmp 'pip-cache'
        $env:XDG_CACHE_HOME = Join-Path $tmp 'cache'
        $ref = if ($env:GRIMOIRE_RUN_REF) { $env:GRIMOIRE_RUN_REF } else { $DefaultRef }
        Get-Source $tool $ref $tmp
        $env_ = Initialize-Python $tool $tmp
        $sep = if ($OnWindows) { ';' } else { ':' }
        $env:PATH = "$($env_.VenvBin)$sep$($env:PATH)"
        Say "running $($tool.Name) (temporary copy, removed afterwards)"
        & $env_.Py (Join-Path (Join-Path $tmp 'app') $tool.Entry) @rest
        $global:LASTEXITCODE = $LASTEXITCODE
    } finally {
        $env:PIP_CACHE_DIR = $saved.PIP; $env:XDG_CACHE_HOME = $saved.XDG; $env:PATH = $saved.PATH
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Say 'cleaned up temporary files'
    }
}

function Invoke-List {
    foreach ($t in $Tools.Keys) {
        $inst = Find-Install (Get-Tool $t) $null
        $where = if ($inst) { "$($inst.Dest) ($($inst.Meta.ref))" } else { '-' }
        '{0,-12} {1,-28} {2}' -f $t, $Tools[$t].Dir, $where
    }
}

function Show-Usage {
    [Console]::Error.WriteLine("usage: grimoire.ps1 install|update|uninstall|run|list <tool> [options]")
    [Console]::Error.WriteLine("tools: $($Tools.Keys -join ', ')")
}

$cmd = if ($GrimoireArgs.Count -gt 0) { [string]$GrimoireArgs[0] } else { '' }
$toolName = if ($GrimoireArgs.Count -gt 1) { [string]$GrimoireArgs[1] } else { '' }
$restArgs = if ($GrimoireArgs.Count -gt 2) { [string[]]$GrimoireArgs[2..($GrimoireArgs.Count - 1)] } else { [string[]]@() }
switch ($cmd) {
    'install' { Invoke-Install $toolName $restArgs }
    { $_ -in 'update', 'upgrade' } { Invoke-Update $toolName $restArgs }
    { $_ -in 'uninstall', 'remove' } { Invoke-Uninstall $toolName $restArgs }
    'run' { Invoke-Run $toolName $restArgs }
    'list' { Invoke-List }
    default { Show-Usage; if ($cmd -and $cmd -notin 'help', '-h', '--help') { Fail "unknown command '$cmd'" } }
}
