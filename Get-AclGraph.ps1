<#
.SYNOPSIS
    ACL-Graph+ - Funde-zentrierter Verzeichnis-Knotengraph mit effektiven Rechten,
    Secret-Erkennung in Konfigs, Default-Ordner-Erkennung und Skip-Liste.

.DESCRIPTION
    Wie ACL-Graph, zusaetzlich:
      - Inhalts-Scan lesbarer Konfig-/Skript-Dateien auf Secrets (Passwoerter,
        ConnectionStrings, API-Keys, AWS, Private-Keys, Token) mit Kontext.
      - Default-/Standard-Ordner werden erkannt; sind sie unveraendert (keine
        abweichenden Rechte, keine Funde/Secrets im Teilbaum), werden sie im
        Output grau und eingeklappt dargestellt.
      - Eigene Skip-Liste (-Skip): Ordner/Namen, die gar nicht erst betreten werden.
      - Grosse Dateien werden beim Inhalts-Scan uebersprungen und markiert.

    WARNUNG: Der HTML-Report kann Klartext-Secrets enthalten. Secret-Werte sind
    standardmaessig verdeckt und werden erst auf Klick eingeblendet. Report nur
    lokal oeffnen, nicht weitergeben.

.PARAMETER Path
    Wurzelverzeichnis des Scans. Default: aktuelles Verzeichnis.

.PARAMETER OutFile
    Zieldatei fuer den HTML-Report. Default: .\aclgraph.html

.PARAMETER Depth
    Maximale Rekursionstiefe. 0 = unbegrenzt. Default: 0.

.PARAMETER Skip
    Liste von Namens-/Pfadmustern (Regex), die beim Scan uebersprungen werden.
    Beispiel: -Skip 'WinSxS','node_modules','\.git$'

.PARAMETER ScanExtensions
    Zusaetzliche Dateiendungen (ohne Punkt) fuer den Secret-Inhalts-Scan,
    zusaetzlich zum Default-Set (.config .env .ini .json .xml .ps1 .bat .yaml).
    Beispiel: -ScanExtensions 'conf','properties'

.PARAMETER SecretRegex
    Zusaetzliche eigene Regex-Muster fuer die Secret-Erkennung.
    Beispiel: -SecretRegex 'INTERNAL_TOKEN\s*=\s*\S+'

.PARAMETER MaxScanMB
    Dateien groesser als dieser Wert (MB) werden beim Inhalts-Scan uebersprungen
    und markiert. Default: 5.

.PARAMETER DefaultDirs
    Pfadmuster (Regex), die als "Default-/Standard-Ordner" gelten. Default deckt
    typische Windows-Systemordner ab.

.PARAMETER ExcludeReparse
    Reparse-Points (Symlinks/Junctions) nicht verfolgen. Default: an.

.EXAMPLE
    .\Get-AclGraph.ps1 -Path 'C:\inetpub' -OutFile report.html

.EXAMPLE
    .\Get-AclGraph.ps1 -Path C:\ -Depth 4 -Skip 'WinSxS','node_modules' -MaxScanMB 2
#>

[CmdletBinding()]
param(
    [string]$Path = (Get-Location).Path,
    [string]$OutFile = (Join-Path (Get-Location).Path 'aclgraph.html'),
    [int]$Depth = 0,
    [string[]]$Skip = @(),
    [string[]]$ScanExtensions = @(),
    [string[]]$SecretRegex = @(),
    [int]$MaxScanMB = 5,
    [string[]]$DefaultDirs = @(
        '^[A-Z]:\\Windows($|\\)', 'WinSxS', '\\System32($|\\)', '\\SysWOW64($|\\)',
        '\\Microsoft\.NET\\', '\\assembly\\', '\\Installer($|\\)',
        '\\Program Files\\Common Files\\', '\\Program Files \(x86\)\\Common Files\\'
    ),
    [switch]$ExcludeReparse = $true
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Identitaet des aktuellen Benutzers + alle SIDs aus dem Access-Token
# ---------------------------------------------------------------------------
$current   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$mySids    = New-Object System.Collections.Generic.HashSet[string]
[void]$mySids.Add($current.User.Value)
foreach ($g in $current.Groups) { [void]$mySids.Add($g.Value) }
$userName  = $current.Name

Write-Host "Scanne als: $userName" -ForegroundColor Cyan
Write-Host "Wurzel    : $Path"     -ForegroundColor Cyan
if ($Skip.Count) { Write-Host "Skip      : $($Skip -join ', ')" -ForegroundColor DarkYellow }

# Rechte-Bits
$R_READ    = [System.Security.AccessControl.FileSystemRights]::ReadData -bor `
             [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor `
             [System.Security.AccessControl.FileSystemRights]::ReadPermissions
$R_WRITE   = [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
             [System.Security.AccessControl.FileSystemRights]::AppendData -bor `
             [System.Security.AccessControl.FileSystemRights]::WriteAttributes
$R_DELETE  = [System.Security.AccessControl.FileSystemRights]::Delete
$R_EXEC    = [System.Security.AccessControl.FileSystemRights]::ExecuteFile
$R_FULL    = [System.Security.AccessControl.FileSystemRights]::FullControl
$R_MODIFY  = [System.Security.AccessControl.FileSystemRights]::Modify
$R_WRITEDAC= [System.Security.AccessControl.FileSystemRights]::ChangePermissions
$R_TAKEOWN = [System.Security.AccessControl.FileSystemRights]::TakeOwnership

# Sensible Pfade -> Funde dort sind interessanter
$sensitivePatterns = @(
    'Program Files', 'Windows\\System32', 'Windows\\SysWOW64',
    'ProgramData', '\\Services\\', 'inetpub', 'scheduled'
)

# Dateiendungen fuer Secret-Inhalts-Scan (Default + benutzerdefiniert)
$scanExt = @('config','env','ini','json','xml','ps1','bat','yaml','yml') + ($ScanExtensions | ForEach-Object { $_.TrimStart('.') })
$scanExt = $scanExt | Select-Object -Unique

# Secret-Muster: Name + Regex (case-insensitive). Eigene Muster werden ergaenzt.
$secretRules = @(
    @{ Name='Passwort';         Rx='(?i)(password|passwort|\bpwd\b|\bpass\b)\s*[:=]\s*["'']?([^"''\s,;<>]{4,})' }
    @{ Name='ConnectionString'; Rx='(?i)(connectionstring|server\s*=.*?;.*?password\s*=)\s*["'']?([^"''<>]{6,})' }
    @{ Name='API-Key';          Rx='(?i)(api[_-]?key|apikey|client[_-]?secret)["'']?\s*[:=]\s*["'']?([A-Za-z0-9_\-]{12,})' }
    @{ Name='AWS-Key';          Rx='(AKIA[0-9A-Z]{16})' }
    @{ Name='Private-Key';      Rx='(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)' }
    @{ Name='Token/Bearer';     Rx='(?i)(bearer\s+[A-Za-z0-9_\-\.]{16,}|token["'']?\s*[:=]\s*["'']?[A-Za-z0-9_\-\.]{16,})' }
)
foreach ($r in $SecretRegex) { $secretRules += @{ Name='Custom'; Rx=$r } }

$maxBytes = $MaxScanMB * 1MB

function Get-EffectiveRights {
    # Erwartet ACE-Regeln bereits in SID-Form (siehe Scan-Item). Dadurch
    # entfaellt das teure .Translate() pro ACE/Knoten komplett.
    param($Rules)
    $allow = 0; $deny = 0
    if (-not $Rules) { return [pscustomobject]@{ Mask=0; Denied=$false } }
    foreach ($ace in $Rules) {
        $sid = $ace.IdentityReference.Value
        if ($mySids.Contains($sid)) {
            $rights = [int]$ace.FileSystemRights
            if ($ace.AccessControlType -eq 'Allow') { $allow = $allow -bor $rights }
            else                                     { $deny  = $deny  -bor $rights }
        }
    }
    $effective = $allow -band (-bnot $deny)
    [pscustomobject]@{ Mask = $effective; Denied = ($deny -ne 0) }
}

function Convert-RightsToFlags {
    param([int]$Mask)
    $f = @()
    if ($Mask -band [int]$R_READ)     { $f += 'R' }
    if ($Mask -band [int]$R_WRITE)    { $f += 'W' }
    if ($Mask -band [int]$R_EXEC)     { $f += 'X' }
    if ($Mask -band [int]$R_DELETE)   { $f += 'D' }
    if ($Mask -band [int]$R_WRITEDAC) { $f += 'P' }
    if ($Mask -band [int]$R_TAKEOWN)  { $f += 'O' }
    if (($Mask -band [int]$R_FULL) -eq [int]$R_FULL) { $f = @('FULL') }
    ,$f
}

function Test-Sensitive {
    param([string]$FullPath)
    foreach ($p in $sensitivePatterns) { if ($FullPath -match $p) { return $true } }
    return $false
}

function Test-SkipMatch {
    param([string]$Name, [string]$FullPath)
    foreach ($p in $Skip) {
        if ($Name -match $p -or $FullPath -match $p) { return $true }
    }
    return $false
}

function Test-DefaultDir {
    param([string]$FullPath)
    foreach ($p in $DefaultDirs) { if ($FullPath -match $p) { return $true } }
    return $false
}

function Get-FileKind {
    param($Item, [bool]$IsDir)
    if ($IsDir) { return 'dir' }
    $ext = ([System.IO.Path]::GetExtension($Item.Name)).TrimStart('.').ToLower()
    switch -Regex ($ext) {
        '^(config|env|ini|json|xml|yaml|yml|conf|properties)$' { return 'config' }
        '^(ps1|bat|cmd|sh|vbs)$'                               { return 'script' }
        '^(pfx|pem|key|cer|crt|p12)$'                          { return 'key' }
        '^(zip|7z|rar|tar|gz|bak|mdf|sqlite|db)$'              { return 'archive' }
        default                                                { return 'file' }
    }
}

# Liest eine Datei und sucht Secret-Muster. Gibt Liste von Treffern zurueck
# (Typ, Zeile, Kontext +/-1, Position des Treffers in der Trefferzeile).
function Find-Secrets {
    param([string]$FullPath, [long]$Size)
    $result = [pscustomobject]@{ secrets=@(); skipped=$null }
    if ($Size -gt $maxBytes) {
        $mb = [math]::Round($Size / 1MB, 1)
        $result.skipped = "zu gross ($mb MB > $MaxScanMB MB)"
        return $result
    }
    $lines = $null
    try { $lines = [System.IO.File]::ReadAllLines($FullPath) }
    catch { $result.skipped = 'nicht lesbar'; return $result }

    $hits = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.Length -eq 0) { continue }
        foreach ($rule in $secretRules) {
            $m = [regex]::Match($line, $rule.Rx)
            if ($m.Success) {
                # Treffer-Spanne: bevorzugt die letzte Gruppe (der eigentliche Wert), sonst ganzer Match
                $g = $m.Groups[$m.Groups.Count - 1]
                $from = if ($g.Success -and $g.Length -gt 0) { $g.Index } else { $m.Index }
                $to   = if ($g.Success -and $g.Length -gt 0) { $g.Index + $g.Length } else { $m.Index + $m.Length }

                # Lange Zeile auf Fenster +/-40 Zeichen um den Treffer kuerzen
                $ctxLine = $line; $shift = 0; $prefix=''; $suffix=''
                if ($line.Length -gt 120) {
                    $winStart = [math]::Max(0, $from - 40)
                    $winEnd   = [math]::Min($line.Length, $to + 40)
                    if ($winStart -gt 0) { $prefix = '...' }
                    if ($winEnd -lt $line.Length) { $suffix = '...' }
                    $ctxLine = $prefix + $line.Substring($winStart, $winEnd - $winStart) + $suffix
                    $shift = $winStart - $prefix.Length
                }

                $ctx = @()
                if ($i - 1 -ge 0) { $ctx += $lines[$i-1] }
                $ctx += $ctxLine
                if ($i + 1 -lt $lines.Count) { $ctx += $lines[$i+1] }
                $hitIdx = if ($i - 1 -ge 0) { 1 } else { 0 }

                $hits += [pscustomobject]@{
                    type    = $rule.Name
                    line    = $i + 1
                    ctx     = $ctx
                    hitLine = $hitIdx
                    hitFrom = [math]::Max(0, $from - $shift)
                    hitTo   = [math]::Max(0, $to   - $shift)
                }
                break  # pro Zeile nur ein Treffer
            }
        }
        if ($hits.Count -ge 25) { break }  # Deckel pro Datei
    }
    $result.secrets = $hits
    return $result
}

$nodeId = 0
$nodes  = New-Object System.Collections.Generic.List[object]
$skippedDirs = 0
# Alle waehrend des Scans gesehenen SIDs (Owner + ACE). Werden NICHT pro Knoten,
# sondern am Ende EINMAL gebuendelt in Namen aufgeloest.
$allSids = New-Object System.Collections.Generic.HashSet[string]

function Scan-Item {
    param($Item, [int]$Level, [int]$ParentId)

    $script:nodeId++
    $myId = $script:nodeId

    $isDir = $Item.PSIsContainer
    $full  = $Item.FullName

    $acl = $null; $aclError = $null
    try { $acl = Get-Acl -LiteralPath $full -ErrorAction Stop }
    catch { $aclError = $_.Exception.Message }

    # ACEs + Owner bewusst in SID-Form holen: .Access/.Owner wuerden hier pro
    # Knoten eine Namensaufloesung (ggf. Domaenen-/Netzwerk-Lookup) ausloesen.
    $rulesSid = $null
    if ($acl) {
        try { $rulesSid = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) } catch {}
    }

    $eff   = Get-EffectiveRights -Rules $rulesSid
    $flags = Convert-RightsToFlags -Mask $eff.Mask

    $owner = $null
    if ($acl) {
        try { $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; [void]$script:allSids.Add($owner) } catch {}
    }

    $aces = @()
    if ($rulesSid) {
        foreach ($ace in $rulesSid) {
            $sid = $ace.IdentityReference.Value
            [void]$script:allSids.Add($sid)
            $aces += [pscustomobject]@{
                sid=$sid; type=[string]$ace.AccessControlType
                rights=[string]$ace.FileSystemRights; inh=[string]$ace.InheritanceFlags; isInh=$ace.IsInherited
            }
        }
    }

    $attrs  = [string]$Item.Attributes
    $hidden = ($Item.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0 -or `
              ($Item.Attributes -band [System.IO.FileAttributes]::System) -ne 0

    $writable  = ($eff.Mask -band [int]$R_WRITE) -ne 0 -or `
                 (($eff.Mask -band [int]$R_MODIFY) -eq [int]$R_MODIFY) -or `
                 (($eff.Mask -band [int]$R_FULL) -eq [int]$R_FULL)
    $readable  = ($eff.Mask -band [int]$R_READ) -ne 0
    $sensitive = Test-Sensitive -FullPath $full
    $alert     = $writable -and $sensitive -and -not $isDir
    $aclWeak   = ($eff.Mask -band [int]$R_WRITEDAC) -ne 0 -or ($eff.Mask -band [int]$R_TAKEOWN) -ne 0
    $kind      = Get-FileKind -Item $Item -IsDir $isDir
    $isDefault = $isDir -and (Test-DefaultDir -FullPath $full)

    $size = $null
    if (-not $isDir) { try { $size = $Item.Length } catch {} }

    # Secret-Scan: nur lesbare Dateien mit passender Endung
    $secrets = @(); $skipped = $null
    if (-not $isDir -and $readable) {
        $ext = ([System.IO.Path]::GetExtension($Item.Name)).TrimStart('.').ToLower()
        if ($scanExt -contains $ext) {
            $sc = Find-Secrets -FullPath $full -Size ([long]($size))
            $secrets = $sc.secrets
            $skipped = $sc.skipped
        }
    }

    $nodes.Add([pscustomobject]@{
        id=$myId; parent=$ParentId; level=$Level; name=$Item.Name; full=$full
        isDir=$isDir; hidden=$hidden; flags=$flags; writable=$writable; alert=$alert
        aclWeak=$aclWeak; denied=$eff.Denied; owner=$owner; attrs=$attrs; size=$size
        aces=$aces; aclError=$aclError; kind=$kind; isDefault=$isDefault
        secrets=$secrets; skipped=$skipped
    })

    if ($isDir) {
        if ($ExcludeReparse -and (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) { return }
        if ($Depth -gt 0 -and $Level -ge $Depth) { return }
        $children = $null
        try { $children = Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop | Sort-Object -Property @{Expression='PSIsContainer';Descending=$true}, Name }
        catch { return }
        foreach ($c in $children) {
            if (Test-SkipMatch -Name $c.Name -FullPath $c.FullName) { $script:skippedDirs++; continue }
            Scan-Item -Item $c -Level ($Level+1) -ParentId $myId
        }
    }
}

$root = Get-Item -LiteralPath $Path -Force
Scan-Item -Item $root -Level 0 -ParentId 0

# ---------------------------------------------------------------------------
# Nachbearbeitung: "Default unveraendert" bestimmen.
# Ein Default-Ordner gilt als unveraendert, wenn in seinem Teilbaum KEIN
# Fund (alert), KEIN Secret und KEINE writable-Datei liegt. Nur dann wird er
# im Output grau + eingeklappt. Liegt etwas Interessantes drin -> normal.
# ---------------------------------------------------------------------------
$byIdH = @{}; foreach ($n in $nodes) { $byIdH[$n.id] = $n }
$childH = @{}
foreach ($n in $nodes) {
    if (-not $childH.ContainsKey($n.parent)) { $childH[$n.parent] = New-Object System.Collections.Generic.List[int] }
    $childH[$n.parent].Add($n.id)
}
function Test-SubtreeClean {
    param([int]$Id)
    $n = $byIdH[$Id]
    if ($n.alert -or ($n.secrets -and $n.secrets.Count -gt 0) -or ($n.writable -and -not $n.isDir)) { return $false }
    if ($childH.ContainsKey($Id)) {
        foreach ($cid in $childH[$Id]) { if (-not (Test-SubtreeClean -Id $cid)) { return $false } }
    }
    return $true
}
foreach ($n in $nodes) {
    $clean = $false
    if ($n.isDefault) { $clean = Test-SubtreeClean -Id $n.id }
    $n | Add-Member -NotePropertyName defaultClean -NotePropertyValue $clean -Force
}

Write-Host "Knoten gescannt: $($nodes.Count)" -ForegroundColor Green
if ($skippedDirs) { Write-Host "Per Skip-Liste uebersprungen: $skippedDirs" -ForegroundColor DarkYellow }
$secretFiles = ($nodes | Where-Object { $_.secrets -and $_.secrets.Count -gt 0 }).Count
if ($secretFiles) { Write-Host "Dateien mit Secret-Verdacht: $secretFiles" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# SID-Aufloesung gebuendelt (Phase B): jede eindeutige SID genau EINMAL in
# einen Namen uebersetzen, statt pro ACE/Knoten. Spart bei Domaenen-Lookups
# massiv Zeit (Dutzende statt Zigtausende Aufloesungen).
# ---------------------------------------------------------------------------
$sidName = @{}
foreach ($sid in $allSids) {
    try   { $sidName[$sid] = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $sidName[$sid] = $sid }   # nicht aufloesbare SID -> SID-String anzeigen
}
Write-Host "Eindeutige SIDs aufgeloest: $($allSids.Count)" -ForegroundColor Green

# Phase C: aufgeloeste Namen in die Knoten einsetzen, damit das HTML
# (liest owner und ace.id) unveraendert funktioniert.
foreach ($n in $nodes) {
    if ($n.owner) { $n.owner = $sidName[$n.owner] }
    foreach ($a in $n.aces) {
        $a | Add-Member -NotePropertyName id -NotePropertyValue ($sidName[$a.sid]) -Force
    }
}

# ---------------------------------------------------------------------------
# JSON fuer das HTML serialisieren
# ---------------------------------------------------------------------------
$json = $nodes | ConvertTo-Json -Depth 8 -Compress

$alertCount   = ($nodes | Where-Object { $_.alert }).Count
$writeCount   = ($nodes | Where-Object { $_.writable }).Count
$hiddenCount  = ($nodes | Where-Object { $_.hidden }).Count
$secretCount  = ($nodes | Where-Object { $_.secrets -and $_.secrets.Count -gt 0 }).Count
$skipScanCount= ($nodes | Where-Object { $_.skipped }).Count
$genDate      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$userJson     = $userName | ConvertTo-Json

Add-Type -AssemblyName System.Web
$pathEnc = [System.Web.HttpUtility]::HtmlEncode($Path)
$userEnc = [System.Web.HttpUtility]::HtmlEncode($userName)
$secretWarn = if ($secretCount -gt 0) { 'block' } else { 'none' }

$html = @"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACL-Graph+ &mdash; $pathEnc</title>
<style>
  :root{
    --bg:#0f1115;--panel:#171a21;--panel2:#1d2129;--line:#2a2f3a;
    --fg:#d7dce3;--muted:#7f8896;--tert:#5a626e;--accent:#5ab0ff;
    --dir:#22344a;--dirbd:#3a5577;--dirfg:#9db4ff;
    --file:#1d2129;--filebd:#2a2f3a;--filefg:#aab2bf;
    --w:#332a12;--wbd:#7a6320;--wfg:#ffcf5a;
    --alert:#3a1414;--alertbd:#ff5d5d;--alertfg:#ff7b7b;
    --ok:#46c98b;--weakfg:#ff9b3d;--secret:#ff5d5d;
  }
  *{box-sizing:border-box}
  body{margin:0;font:13px/1.5 ui-monospace,Consolas,monospace;background:var(--bg);color:var(--fg)}
  header{padding:14px 18px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:14px;align-items:center}
  header h1{font-size:15px;margin:0;font-weight:600;color:#fff}
  header .meta{color:var(--muted);font-size:12px}
  .stats{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
  .chip{padding:3px 9px;border-radius:20px;background:var(--panel2);border:1px solid var(--line);font-size:11px}
  .chip b{color:#fff}.chip.alert b{color:var(--alertfg)}.chip.w b{color:var(--wfg)}.chip.secret b{color:var(--secret)}
  .warnbar{display:$secretWarn;padding:8px 18px;background:#3a1414;color:#ffc4c4;font-size:12px;border-bottom:1px solid var(--alertbd)}
  .warnbar b{color:#fff}
  .bar{padding:8px 18px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .bar button{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:6px;cursor:pointer;font:inherit}
  .bar button:hover{border-color:var(--accent)}
  .bar label{display:flex;align-items:center;gap:5px;color:var(--muted);font-size:12px;cursor:pointer}
  input#filter{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:5px 9px;border-radius:6px;width:280px;font:inherit}
  .fhint{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--tert);padding:4px 18px;background:var(--panel)}
  .fhint b{color:var(--muted)}
  #wrap{position:relative;width:100%;height:calc(100vh - 168px);background:#0c0e12;overflow:hidden;cursor:grab}
  #wrap.drag{cursor:grabbing}
  #stage{position:absolute;top:0;left:0;transform-origin:0 0}
  svg#edges{position:absolute;top:0;left:0;overflow:visible;pointer-events:none}
  .gnode{position:absolute;border-radius:8px;border:1px solid var(--filebd);padding:7px 10px;font-size:12px;line-height:1.35;
         cursor:pointer;user-select:none;background:var(--file);min-width:140px;max-width:250px;transition:box-shadow .1s}
  .gnode:hover{box-shadow:0 0 0 2px var(--accent)}
  .gnode .nm{font-weight:500;display:flex;align-items:center;gap:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--filefg)}
  .gnode .nm i{flex:none}
  .gnode .fl{font-size:11px;color:var(--muted);margin-top:2px;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
  .gnode .toggle{margin-left:auto;flex:none;color:var(--muted)}
  .gnode.dir{background:var(--dir);border-color:var(--dirbd)}.gnode.dir .nm{color:var(--dirfg)}
  .gnode.write{background:var(--w);border-color:var(--wbd)}.gnode.write .nm{color:var(--wfg)}
  .gnode.alert{background:var(--alert);border:2px solid var(--alertbd)}.gnode.alert .nm{color:var(--alertfg)}
  .gnode.def{background:transparent;border:1px dashed var(--tert);opacity:.6}.gnode.def .nm{color:var(--tert)}
  .gnode.dim{opacity:.18}.gnode.hit{box-shadow:0 0 0 2px var(--wfg)}
  .badge{font-size:10px;padding:1px 6px;border-radius:10px;font-family:ui-monospace,Consolas,monospace;display:inline-flex;align-items:center;gap:3px}
  .b-secret{background:#3a1414;color:var(--secret)}
  .b-skip{background:var(--panel2);color:var(--tert);border:1px solid var(--line)}
  .b-def{background:var(--panel2);color:var(--tert)}
  .legend{position:absolute;top:10px;right:10px;z-index:5;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:11px}
  .legend div{display:flex;align-items:center;gap:6px;margin:2px 0}
  .sw{width:12px;height:12px;border-radius:3px;flex:none}
  .detail{position:absolute;bottom:10px;left:10px;z-index:6;width:360px;max-height:64vh;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;font-size:12px;display:none}
  .detail.show{display:block}
  .detail .t{font-size:14px;color:#fff;word-break:break-all}
  .detail .p{color:var(--muted);font-size:11px;word-break:break-all;margin:2px 0 10px}
  .detail .kv{display:grid;grid-template-columns:90px 1fr;gap:3px 10px}
  .detail .kv .k{color:var(--muted)}
  .detail .x{float:right;cursor:pointer;color:var(--muted);font-size:18px;line-height:1}.detail .x:hover{color:#fff}
  table.ace{width:100%;border-collapse:collapse;font-size:11px;margin-top:10px}
  table.ace th{text-align:left;color:var(--muted);font-weight:500;padding:4px;border-bottom:1px solid var(--line)}
  table.ace td{padding:4px;border-bottom:1px solid var(--panel2);vertical-align:top;word-break:break-word}
  .ace .allow{color:var(--ok)}.ace .deny{color:var(--alertfg)}.ace .inh{color:var(--muted);font-size:10px}
  .secblock{margin-top:10px;border-top:1px solid var(--line);padding-top:8px}
  .secblock>.h{display:flex;align-items:center;gap:6px;color:var(--secret);font-size:11px;margin-bottom:6px}
  .sechit{margin-bottom:8px}
  .sechit .lbl{display:flex;align-items:center;gap:6px;color:var(--secret);font-size:11px;margin-bottom:3px}
  .sechit .reveal{margin-left:auto;background:var(--bg);border:1px solid var(--line);color:var(--muted);
    padding:1px 7px;border-radius:5px;cursor:pointer;font:inherit;font-size:10px}
  .sechit .reveal:hover{border-color:var(--accent);color:var(--accent)}
  .sechit pre{margin:0;background:#0c0e12;border-radius:6px;padding:6px 8px;font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.5;border:1px solid var(--line)}
  .sechit pre .ln{color:var(--tert);user-select:none}
  .sechit pre .secval{color:var(--secret);background:#3a1414;padding:0 2px;border-radius:2px}
  .sechit pre .secval.masked{color:var(--tert);background:var(--panel2)}
  .skipnote{margin-top:8px;color:var(--tert)}
  #nav{position:absolute;bottom:10px;right:10px;z-index:6;display:flex;align-items:flex-end;gap:8px}
  #nav .valbox{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 9px;font-size:11px;color:var(--muted);line-height:1.6}
  #nav .valbox b{color:var(--fg);font-weight:600}#nav .valbox .z{color:var(--accent)}
  #nav .compass{background:var(--panel);border:1px solid var(--line);border-radius:8px;cursor:pointer;display:block}
  #nav .compass:hover{border-color:var(--accent)}
</style>
</head>
<body>
<header>
  <div><h1>ACL-Graph+</h1><div class="meta">Wurzel: $pathEnc &nbsp;|&nbsp; Benutzer: $userEnc &nbsp;|&nbsp; $genDate</div></div>
  <div class="stats">
    <span class="chip">Knoten <b>$($nodes.Count)</b></span>
    <span class="chip w">beschreibbar <b>$writeCount</b></span>
    <span class="chip alert">Funde <b>$alertCount</b></span>
    <span class="chip secret">Secrets <b>$secretCount</b></span>
    <span class="chip">versteckt <b>$hiddenCount</b></span>
  </div>
</header>
<div class="warnbar"><b>&#9888; Achtung:</b> Dieser Report enth&auml;lt potenzielle Klartext-Secrets ($secretCount Datei(en)). Werte sind verdeckt &ndash; Klick auf &bdquo;einblenden&ldquo; zeigt sie. Nur lokal &ouml;ffnen, nicht weitergeben.</div>
<div class="bar">
  <button onclick="gZoom(1.25)">+</button><button onclick="gZoom(0.8)">&minus;</button>
  <button onclick="gFit()">&#9678; Alles</button>
  <button onclick="gExpandAll()">&#10063; Pfade entfalten</button>
  <button onclick="gCollapse()">&#10064; Nur Funde</button>
  <label><input type="checkbox" id="showdef" onchange="toggleDefaults(this.checked)"> Default-Ordner einblenden</label>
  <input id="filter" type="text" placeholder="Filtern: config -test" oninput="applyFilter(this.value)" style="margin-left:auto">
</div>
<div class="fhint"><b>Filter:</b> wort = enthalten &middot; -wort = ausschlie&szlig;en &middot; mehrere mit Leerzeichen (z.B. <b>config -backup -test</b>)</div>
<div id="wrap">
  <div class="legend">
    <div><span class="sw" style="background:var(--dir);border:1px solid var(--dirbd)"></span> Verzeichnis</div>
    <div><span class="sw" style="background:var(--w);border:1px solid var(--wbd)"></span> beschreibbar</div>
    <div><span class="sw" style="background:var(--alert);border:2px solid var(--alertbd)"></span> Fund (writable+sensibel)</div>
    <div><span class="sw" style="background:#3a1414"></span> &#128273; Secret im Inhalt</div>
    <div><span class="sw" style="background:transparent;border:1px dashed var(--tert)"></span> Default-Ordner (unver&auml;ndert)</div>
    <div><span class="sw" style="background:var(--panel2);border:1px solid var(--line)"></span> nicht gescannt (zu gro&szlig;)</div>
  </div>
  <svg id="edges"></svg>
  <div id="stage"></div>
  <div class="detail" id="detail"></div>
  <div id="nav">
    <div class="valbox">x <b id="cx">0</b><br>y <b id="cy">0</b><br>z <span class="z" id="cz">100%</span></div>
    <svg class="compass" id="compass" width="60" height="60" viewBox="0 0 60 60" onclick="gFit()" role="img" aria-label="Position zur&uuml;cksetzen">
      <defs><marker id="ah" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
        <path d="M2 1L8 5L2 9" fill="none" stroke="#7f8896" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>
      <line x1="30" y1="53" x2="30" y2="7" stroke="#7f8896" stroke-width="1" marker-end="url(#ah)"/>
      <line x1="7" y1="30" x2="53" y2="30" stroke="#7f8896" stroke-width="1" marker-end="url(#ah)"/>
      <text x="34" y="13" font-family="serif" font-style="italic" font-size="10" fill="#7f8896">y</text>
      <text x="49" y="26" font-family="serif" font-style="italic" font-size="10" fill="#7f8896">x</text>
      <circle id="cdot" cx="30" cy="30" r="3.5" fill="#5ab0ff" stroke="#171a21" stroke-width="1.5" style="transition:cx .1s,cy .1s"/>
    </svg>
  </div>
</div>

<script>
const NODES = $json;
const CURRENT_USER = $userJson;
const byId={},kids={};
NODES.forEach(n=>{byId[n.id]=n;(kids[n.parent]=kids[n.parent]||[]).push(n);});
NODES.forEach(n=>n._onPath=false);
NODES.filter(n=>n.alert||(n.secrets&&n.secrets.length)).forEach(a=>{let c=a.id;while(c&&byId[c]){byId[c]._onPath=true;c=byId[c].parent;}});
NODES.forEach(n=>{n._expanded=n._onPath&&n.isDir;n._showAll=false;n._m=false;n._md=false;});
if(!NODES.some(n=>n.alert||(n.secrets&&n.secrets.length))){(kids[0]||[]).forEach(r=>{if(!r.defaultClean)r._expanded=r.isDir;});}

const stage=document.getElementById('stage'),edges=document.getElementById('edges'),
      wrap=document.getElementById('wrap'),detail=document.getElementById('detail');
const COLW=260,ROWH=64;
let term={inc:[],exc:[]};
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function flagStr(f){return f&&f.length?'['+f.join(' ')+']':'-- kein Zugriff --';}
function gcls(n){
  if(n.isDir&&n.isDefault&&n.defaultClean)return 'def';
  return n.alert?'alert':((n.secrets&&n.secrets.length)?'alert':(n.writable?'write':(n.isDir?'dir':'file')));
}
function kindIcon(n){
  if(n.isDir)return n._expanded?'&#128194;':'&#128193;';
  if(n.kind==='config')return '&#9881;';
  if(n.kind==='script')return '&#62;_';
  if(n.kind==='key')return '&#128273;';
  if(n.kind==='archive')return '&#128230;';
  return n.hidden?'&#128065;':'&#128196;';
}

function parseFilter(v){
  const inc=[],exc=[];
  v.toLowerCase().split(/\s+/).filter(Boolean).forEach(t=>{
    if(t.startsWith('-')&&t.length>1)exc.push(t.slice(1));else inc.push(t);
  });
  return {inc,exc};
}
function nodeMatches(n){
  const nm=n.name.toLowerCase();
  if(term.exc.some(e=>nm.includes(e)))return false;
  if(term.inc.length&&!term.inc.some(i=>nm.includes(i)))return false;
  return true;
}
const filtering=()=>term.inc.length||term.exc.length;

function applyFilter(v){
  term=parseFilter(v);
  NODES.forEach(n=>{n._m=false;n._md=false;});
  if(filtering()){
    NODES.forEach(n=>{n._m=nodeMatches(n);});
    NODES.filter(n=>n._m).forEach(m=>{let c=byId[m.parent];while(c){c._md=true;c._expanded=true;c._showAll=true;c=byId[c.parent];}});
  }else{
    NODES.forEach(n=>{n._expanded=n._onPath&&n.isDir;n._showAll=false;});
  }
  render();
}

let bounds={maxX:0,maxY:0};
function buildLayout(){
  const rows=[];let rowCursor=0;const filt=filtering();const showDef=document.getElementById('showdef').checked;
  function visF(n){return n._m||n._md;}
  function walk(n,depth){
    n._depth=depth;const ch=kids[n.id]||[];
    if(n.isDir&&n._expanded&&ch.length){
      const start=rowCursor;
      let shown,hidden=[];
      if(filt){shown=ch.filter(visF);}
      else{
        const interesting=c=>c.alert||(c.secrets&&c.secrets.length)||c.writable||c._onPath||c.isDir;
        shown=n._showAll?ch:ch.filter(interesting);
        hidden=n._showAll?[]:ch.filter(c=>!interesting(c));
      }
      shown.forEach(c=>walk(c,depth+1));
      if(hidden.length){rows.push({ellipsis:true,depth:depth+1,row:rowCursor,count:hidden.length,parent:n.id});rowCursor++;}
      n._row=(start+rowCursor-1)/2;
    }else{n._row=rowCursor;rowCursor++;}
    rows.push({node:n,depth,row:n._row});
  }
  (kids[0]||[]).forEach(r=>{
    if(filt&&!visF(r))return;
    walk(r,0);
  });
  return rows;
}

let selId=null;
function render(){
  stage.innerHTML='';bounds={maxX:0,maxY:0};
  const showDef=document.getElementById('showdef').checked;
  buildLayout().forEach(r=>{
    const x=20+r.depth*COLW,y=20+r.row*ROWH;
    const d=document.createElement('div');
    if(r.ellipsis){
      d.className='gnode';d.style.cssText='left:'+x+'px;top:'+y+'px;background:transparent;border:1px dashed var(--tert);min-width:0;color:var(--tert)';
      d.innerHTML='<div class="nm" style="color:var(--tert);font-weight:400">&hellip; '+r.count+' weitere</div>';
      d.onclick=e=>{e.stopPropagation();byId[r.parent]._showAll=true;renderKeepingNode(r.parent);};
    }else{
      const n=r.node;
      d.className='gnode '+gcls(n);
      if(filtering()){if(n._m)d.classList.add('hit');else d.classList.add('dim');}
      d.style.left=x+'px';d.style.top=y+'px';d.dataset.id=n.id;
      const ch=kids[n.id]||[];
      const tog=n.isDir&&ch.length?('<span class="toggle">'+(n._expanded?'&#9662;':'&#9656;')+'</span>'):'';
      let badges='';
      if(n.secrets&&n.secrets.length)badges+='<span class="badge b-secret">&#128273; '+n.secrets.length+'</span>';
      if(n.skipped)badges+='<span class="badge b-skip">&#128065; n.gescannt</span>';
      if(n.isDir&&n.isDefault&&n.defaultClean&&!n._expanded&&ch.length)badges+='<span class="badge b-def">'+ch.length+' eingeklappt</span>';
      d.innerHTML='<div class="nm">'+kindIcon(n)+' '+esc(n.name)+tog+'</div><div class="fl">'+esc(flagStr(n.flags))+badges+'</div>';
      d.onclick=e=>{e.stopPropagation();selectNode(n,d);if(n.isDir&&ch.length){n._expanded=!n._expanded;renderKeepingNode(n.id);}};
    }
    stage.appendChild(d);
    requestAnimationFrame(()=>{bounds.maxX=Math.max(bounds.maxX,x+d.offsetWidth);bounds.maxY=Math.max(bounds.maxY,y+d.offsetHeight);});
  });
  if(selId){const el=stage.querySelector('.gnode[data-id="'+selId+'"]');if(el)el.classList.add('sel');}
  setTimeout(drawEdges,0);
}
function renderKeepingNode(id){
  const before=stage.querySelector('.gnode[data-id="'+id+'"]');
  const oldX=before?before.offsetLeft:null,oldY=before?before.offsetTop:null;
  render();
  if(oldX==null)return;
  requestAnimationFrame(()=>{const after=stage.querySelector('.gnode[data-id="'+id+'"]');if(!after)return;tx+=(oldX-after.offsetLeft)*scale;ty+=(oldY-after.offsetTop)*scale;apply();});
}
function drawEdges(){
  let p='';
  stage.querySelectorAll('.gnode[data-id]').forEach(el=>{
    const n=byId[el.dataset.id];if(!n||n.parent===0)return;
    const pe=stage.querySelector('.gnode[data-id="'+n.parent+'"]');if(!pe)return;
    const x1=pe.offsetLeft+pe.offsetWidth,y1=pe.offsetTop+22,x2=el.offsetLeft,y2=el.offsetTop+22,mx=(x1+x2)/2;
    p+='<path d="M'+x1+' '+y1+' C'+mx+' '+y1+','+mx+' '+y2+','+x2+' '+y2+'" fill="none" stroke="#2a2f3a" stroke-width="1"/>';
  });
  edges.innerHTML=p;
}

function maskVal(s){return s.replace(/./g,'\u2022');}
function selectNode(n,el){
  stage.querySelectorAll('.gnode.sel').forEach(e=>e.classList.remove('sel'));el.classList.add('sel');selId=n.id;
  let aces=(n.aces||[]).map(a=>'<tr><td class="'+(a.type==='Allow'?'allow':'deny')+'">'+a.type+'</td><td>'+esc(a.id)+'</td><td>'+esc(a.rights)+(a.isInh?' <span class="inh">(geerbt)</span>':'')+'</td></tr>').join('')||'<tr><td colspan="3" style="color:var(--muted)">'+(n.aclError?esc(n.aclError):'keine ACEs')+'</td></tr>';
  let html='<span class="x" onclick="closeD()">&times;</span>'+
   '<div class="t">'+kindIcon(n)+' '+esc(n.name)+'</div><div class="p">'+esc(n.full)+'</div>'+
   (n.alert?'<div style="color:var(--alertfg);margin-bottom:6px">&#9888; beschreibbar in sensiblem Pfad &ndash; Hijack-Vektor</div>':'')+
   (n.aclWeak?'<div style="color:var(--weakfg);margin-bottom:6px">&#9888; WRITE_DAC / TAKE_OWNERSHIP</div>':'')+
   '<div class="kv"><span class="k">Effektiv</span><span>'+esc(flagStr(n.flags))+' ('+esc(CURRENT_USER)+')</span>'+
   '<span class="k">Typ</span><span>'+esc(n.kind||(n.isDir?'dir':'file'))+'</span>'+
   '<span class="k">Owner</span><span>'+esc(n.owner||'?')+'</span>'+
   (n.size!=null?'<span class="k">Gr&ouml;&szlig;e</span><span>'+n.size.toLocaleString()+' B</span>':'')+
   '</div>';
  if(n.skipped)html+='<div class="skipnote">&#128065; Inhalt nicht gescannt: '+esc(n.skipped)+'</div>';
  if(n.secrets&&n.secrets.length){
    html+='<div class="secblock"><div class="h">&#128273; '+n.secrets.length+' Secret-Treffer</div>';
    n.secrets.forEach((s,si)=>{
      const lines=s.ctx.map((l,i)=>{
        const lineNo=s.line - s.hitLine + i;
        if(i===s.hitLine){
          const before=esc(l.slice(0,s.hitFrom)),val=l.slice(s.hitFrom,s.hitTo),after=esc(l.slice(s.hitTo));
          return '<span class="ln">'+lineNo+'</span>  '+before+'<span class="secval masked" data-real="'+esc(val)+'" data-mask="'+esc(maskVal(val))+'">'+esc(maskVal(val))+'</span>'+after;
        }
        return '<span class="ln">'+lineNo+'</span>  '+esc(l);
      }).join('\n');
      html+='<div class="sechit"><div class="lbl">&#128273; '+esc(s.type)+' &middot; Zeile '+s.line+
            '<button class="reveal" onclick="toggleSecret(this)">einblenden</button></div><pre>'+lines+'</pre></div>';
    });
    html+='</div>';
  }
  html+='<table class="ace"><tr><th>Typ</th><th>Identit&auml;t</th><th>Rechte</th></tr>'+aces+'</table>';
  detail.innerHTML=html;detail.classList.add('show');
}
function toggleSecret(btn){
  const pre=btn.closest('.sechit').querySelector('pre');
  const sv=pre.querySelector('.secval');
  if(!sv)return;
  const masked=sv.classList.contains('masked');
  sv.textContent=masked?sv.dataset.real:sv.dataset.mask;
  sv.classList.toggle('masked',!masked);
  btn.textContent=masked?'verdecken':'einblenden';
}
function closeD(){detail.classList.remove('show');stage.querySelectorAll('.gnode.sel').forEach(e=>e.classList.remove('sel'));selId=null;}
function gExpandAll(){NODES.forEach(n=>{if(n.isDir){n._expanded=true;n._showAll=true;}});render();}
function gCollapse(){NODES.forEach(n=>{n._expanded=n._onPath&&n.isDir;n._showAll=false;});render();closeD();}
function toggleDefaults(on){
  // saubere Default-Ordner gezielt auf-/zuklappen
  NODES.forEach(n=>{ if(n.isDir&&n.isDefault&&n.defaultClean){ n._expanded=on; if(on)n._showAll=true; } });
  render();
}

let scale=1,tx=0,ty=0;
function apply(){stage.style.transform='translate('+tx+'px,'+ty+'px) scale('+scale+')';edges.style.transform=stage.style.transform;updateCoords();}
function updateCoords(){
  const r=wrap.getBoundingClientRect();
  const wx=Math.round((r.width/2-tx)/scale),wy=Math.round((r.height/2-ty)/scale);
  const cx=document.getElementById('cx'),cy=document.getElementById('cy'),cz=document.getElementById('cz'),dot=document.getElementById('cdot');
  if(cx)cx.textContent=wx;if(cy)cy.textContent=wy;if(cz)cz.textContent=Math.round(scale*100)+'%';
  if(dot){
    const nx=Math.max(10,Math.min(50,30+(wx/Math.max(1,bounds.maxX))*40-20+20));
    const ny=Math.max(10,Math.min(50,30+(wy/Math.max(1,bounds.maxY))*40-20+20));
    dot.setAttribute('cx',nx);dot.setAttribute('cy',ny);
  }
}
function gZoom(f){const r=wrap.getBoundingClientRect();zoomAt(r.width/2,r.height/2,f);}
function zoomAt(cx,cy,f){const ns=Math.min(2.5,Math.max(0.2,scale*f));tx=cx-(cx-tx)*(ns/scale);ty=cy-(cy-ty)*(ns/scale);scale=ns;apply();}
function gFit(){const r=wrap.getBoundingClientRect();const s=Math.min(r.width/(bounds.maxX+40),r.height/(bounds.maxY+40),1.4);scale=s>0?s:1;tx=20;ty=Math.max(10,(r.height-bounds.maxY*scale)/2);apply();}

let dragging=false,sx,sy;
wrap.addEventListener('mousedown',e=>{if(e.target.closest('.gnode')||e.target.closest('.detail')||e.target.closest('.legend')||e.target.closest('#nav'))return;dragging=true;wrap.classList.add('drag');sx=e.clientX-tx;sy=e.clientY-ty;});
window.addEventListener('mousemove',e=>{if(!dragging)return;tx=e.clientX-sx;ty=e.clientY-sy;apply();});
window.addEventListener('mouseup',()=>{dragging=false;wrap.classList.remove('drag');});
wrap.addEventListener('wheel',e=>{e.preventDefault();const r=wrap.getBoundingClientRect();zoomAt(e.clientX-r.left,e.clientY-r.top,e.deltaY<0?1.12:0.89);},{passive:false});

setTimeout(()=>{render();setTimeout(gFit,80);},40);
</script>
</body>
</html>
"@

[System.IO.File]::WriteAllText($OutFile, $html, [System.Text.UTF8Encoding]::new($false))
Write-Host "HTML geschrieben: $OutFile" -ForegroundColor Green
if ($secretCount) { Write-Host "WARNUNG: Report enthaelt Klartext-Secrets ($secretCount Datei(en)) - nur lokal oeffnen!" -ForegroundColor Red }
