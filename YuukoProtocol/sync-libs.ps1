<#
  sync-libs.ps1 - keeps the shared binaries in step between this solution and the XRUIOS repo.

  Why this exists: the XRUIOS and Yuuko once carried DIFFERENT builds of PariahCybersecurity.dll that
  both claimed to be version 1.0.0.1, so nothing complained until you compared the bytes. This script
  compares the bytes.

      .\sync-libs.ps1 -Check     only report differences (exit code 1 if there are any)
      .\sync-libs.ps1            fix them:
          1. copy the XRUIOS build of PariahCybersecurity / EclipseLCL / EclipseProject into .\libs
             (the XRUIOS copy always wins)
          2. build YuukoProtocol.Definitions (Release) and copy its DLL into the XRUIOS libs folder

  If your XRUIOS checkout is somewhere else:  .\sync-libs.ps1 -XruiosPath D:\code\The-XRUIOS
#>
param(
    [string]$XruiosPath = (Join-Path $env:USERPROFILE "Documents\GitHub\The-XRUIOS"),
    [switch]$Check
)

$ErrorActionPreference = "Stop"
$xruiosLibs = Join-Path $XruiosPath "libs"
$myLibs     = Join-Path $PSScriptRoot "libs"
if (-not (Test-Path $xruiosLibs)) { throw "Can't find the XRUIOS libs folder at '$xruiosLibs'. Pass -XruiosPath." }

function Short-Hash($path) {
    if (Test-Path $path) { (Get-FileHash $path -Algorithm SHA256).Hash.Substring(0, 10) } else { "<missing>" }
}

$problems = 0

# 1) XRUIOS -> Yuuko
foreach ($name in "PariahCybersecurity.dll", "EclipseLCL.dll", "EclipseProject.dll") {
    $from = Join-Path $xruiosLibs $name
    $to   = Join-Path $myLibs $name
    if ((Short-Hash $from) -eq (Short-Hash $to)) { Write-Host "same:      $name"; continue }
    $problems++
    if ($Check) { Write-Host "DIFFERENT: $name  (XRUIOS $(Short-Hash $from)  vs  Yuuko $(Short-Hash $to))" -ForegroundColor Yellow }
    else        { Copy-Item $from $to -Force; Write-Host "updated:   libs\$name (from the XRUIOS)" }
}

# 2) Yuuko -> XRUIOS (the shared definitions)
$project = Join-Path $PSScriptRoot "YuukoProtocol.Definitions"
dotnet build $project -c Release -v q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Building YuukoProtocol.Definitions failed." }
$built  = Join-Path $project "bin\Release\net8.0\YuukoProtocol.Definitions.dll"
$target = Join-Path $xruiosLibs "YuukoProtocol.Definitions.dll"
if ((Short-Hash $built) -eq (Short-Hash $target)) { Write-Host "same:      YuukoProtocol.Definitions.dll" }
else {
    $problems++
    if ($Check) { Write-Host "DIFFERENT: YuukoProtocol.Definitions.dll  (the copy in the XRUIOS libs is out of date)" -ForegroundColor Yellow }
    else        { Copy-Item $built $target -Force; Write-Host "updated:   XRUIOS libs\YuukoProtocol.Definitions.dll" }
}

if ($Check -and $problems -gt 0) { exit 1 }
