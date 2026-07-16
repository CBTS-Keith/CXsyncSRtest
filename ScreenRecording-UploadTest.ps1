# V26.197.1700 - ScreenRecording-UploadTest.ps1
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Keith Talbot
#
# Diagnoses whether the CallCorp "Screen Recording" desktop app can reach
# its upload endpoints. Detects firewall / TLS-inspection / proxy issues
# that would prevent recordings from uploading.
#
# Sends NO credentials - probes public endpoints with an anonymous PUT.
#
# Appends a timestamped report to CXsyncScreenRecording.txt next to the
# script/exe. Falls back to %LOCALAPPDATA%\CXsyncScreenRecording.txt
# if the exe's own folder isn't writable.
#
# When compiled with ps2exe:
#   Invoke-ps2exe .\ScreenRecording-UploadTest.ps1 .\ScreenRecording-UploadTest.exe -title "Screen Recording Upload Test" -company "CBTS"

[CmdletBinding()]
param(
    [string]$BandId,
    [switch]$NoPause    # skip the "press any key" pause at the end (for scripted runs)
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- figure out where the exe/script lives, and where the log goes ---------

function Get-ExeDirectory {
    # When compiled with ps2exe, $PSScriptRoot is empty. Fall back to the
    # location of the running executable.
    if ($PSScriptRoot) { return $PSScriptRoot }
    try {
        $asm = [System.Reflection.Assembly]::GetEntryAssembly()
        if ($asm -and $asm.Location) {
            return [System.IO.Path]::GetDirectoryName($asm.Location)
        }
    } catch { }
    return (Get-Location).Path
}

$exeDir      = Get-ExeDirectory
$logFileName = 'CXsyncScreenRecording.txt'
$logPath     = Join-Path $exeDir $logFileName

# Test writability of exeDir; if not writable, fall back to LOCALAPPDATA
$writable = $false
try {
    $probe = Join-Path $exeDir ('.write-probe-' + [Guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($probe, 'ok')
    Remove-Item $probe -Force -ErrorAction SilentlyContinue
    $writable = $true
} catch { $writable = $false }

if (-not $writable) {
    $logPath = Join-Path $env:LOCALAPPDATA $logFileName
    try { New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null } catch { }
}

# --- tee output: everything below goes to both console AND the log ---------

$script:LogPath = $logPath

function Log {
    param([string]$Line = '', [ConsoleColor]$Color = 'Gray')
    Write-Host $Line -ForegroundColor $Color
    try { Add-Content -LiteralPath $script:LogPath -Value $Line -Encoding UTF8 } catch { }
}

function Log-Nl {
    param([string]$Line, [ConsoleColor]$Color = 'Gray')
    Write-Host $Line -ForegroundColor $Color -NoNewline
    # We deliberately do NOT append -NoNewline lines to the file individually;
    # the caller finishes the line with a plain Log call, which appends the
    # completed line.
}

function Write-Result {
    param([string]$Label, [string]$Status, [string]$Detail = '')
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Gray' }
    }
    $tag  = "[{0,-4}]" -f $Status
    $line = "  $tag $Label"
    # Console: colored tag + plain label
    Write-Host "  $tag " -ForegroundColor $color -NoNewline
    Write-Host $Label
    # File: single plain line
    try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 } catch { }
    if ($Detail) {
        $dline = "         $Detail"
        Write-Host $dline -ForegroundColor DarkGray
        try { Add-Content -LiteralPath $script:LogPath -Value $dline -Encoding UTF8 } catch { }
    }
}

function Section($t) {
    Log ''
    Log "== $t ==" 'Cyan'
}

# --- session header --------------------------------------------------------

$sep = ('=' * 78)
Log ''
Log $sep 'DarkCyan'
Log ("SCREEN RECORDING -> UPLOAD TEST     {0} UTC" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) 'White'
Log ("Machine : {0}    User : {1}" -f $env:COMPUTERNAME, $env:USERNAME)
Log ("Log file: {0}" -f $script:LogPath) 'Gray'
Log $sep 'DarkCyan'

# --- auto-detect BandId ----------------------------------------------------

if (-not $BandId) {
    $log = Join-Path $env:APPDATA 'Screen Recording\logs\renderer.log'
    if (Test-Path $log) {
        $m = Select-String -Path $log -Pattern 'BandId:\s*(\S+)' |
             Select-Object -Last 1
        if ($m -and $m.Matches[0].Groups[1].Value) {
            $BandId = $m.Matches[0].Groups[1].Value.Trim()
        }
    }
}
if (-not $BandId) { $BandId = 'bnd2' }

Log ("Detected BandId: {0}" -f $BandId) 'Gray'

$hostsToTest = @(
    @{ Host = 'portal.total.care';                Purpose = 'Portal / updater download URL' }
    @{ Host = 'api.callcorp.com';                 Purpose = 'Bootstrap: LocationCodeInfo lookup' }
    @{ Host = 'api.total.care';                   Purpose = 'API fallback host' }
    @{ Host = "api-$BandId.total.care";           Purpose = "*** Upload target (BandId=$BandId) ***" }
)

# --- 1. DNS ----------------------------------------------------------------

Section '1. DNS resolution'
foreach ($h in $hostsToTest) {
    try {
        $r = Resolve-DnsName -Name $h.Host -Type A -ErrorAction Stop -DnsOnly
        $ips = ($r | Where-Object { $_.IPAddress } | Select-Object -Expand IPAddress) -join ', '
        if ($ips) {
            Write-Result -Label ('{0}   ({1})' -f $h.Host, $h.Purpose) -Status 'PASS' -Detail "-> $ips"
        } else {
            Write-Result -Label $h.Host -Status 'FAIL' -Detail 'No A record returned (likely blocked/hijacked)'
        }
    } catch {
        Write-Result -Label $h.Host -Status 'FAIL' -Detail $_.Exception.Message
    }
}

# --- 2. TCP 443 ------------------------------------------------------------

Section '2. TCP 443 reachability'
foreach ($h in $hostsToTest) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($h.Host, 443, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne(5000, $false)
        if ($ok -and $c.Connected) {
            Write-Result -Label ("TCP 443 -> $($h.Host)") -Status 'PASS'
            $c.Close()
        } else {
            Write-Result -Label ("TCP 443 -> $($h.Host)") -Status 'FAIL' -Detail 'Timed out after 5s (firewall / no route)'
            $c.Close()
        }
    } catch {
        Write-Result -Label ("TCP 443 -> $($h.Host)") -Status 'FAIL' -Detail $_.Exception.Message
    }
}

# --- 3. TLS handshake + cert issuer ---------------------------------------

Section '3. TLS handshake (checks for TLS inspection / MITM)'
foreach ($h in $hostsToTest) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($h.Host, 443)
        $ssl = New-Object System.Net.Security.SslStream(
            $tcp.GetStream(), $false,
            { param($s,$c,$ch,$er) $true }
        )
        # Explicit TLS 1.2/1.3 - required because SslStream doesn't consult
        # ServicePointManager.SecurityProtocol (that only affects HttpWebRequest)
        $tlsProtos = [System.Security.Authentication.SslProtocols]::Tls12
        try { $tlsProtos = $tlsProtos -bor [System.Security.Authentication.SslProtocols]::Tls13 } catch { }
        $ssl.AuthenticateAsClient($h.Host, $null, $tlsProtos, $false)
        $cert   = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
        $issuer = ($cert.Issuer -split ',')[0].Replace('CN=','').Trim()
        $expected = @('DigiCert','Amazon',"Let's Encrypt",'Sectigo','GlobalSign','GoDaddy','Go Daddy','Cloudflare','Entrust','ISRG','Google Trust')
        $looksLegit = $false
        foreach ($e in $expected) { if ($issuer -like "*$e*") { $looksLegit = $true; break } }
        # Stash expiry so Section 10 can warn without redoing the handshake
        if (-not $script:CertExpiry) { $script:CertExpiry = @{} }
        $script:CertExpiry[$h.Host] = $cert.NotAfter
        if ($looksLegit) {
            Write-Result -Label $h.Host -Status 'PASS' -Detail "TLS OK, issuer: $issuer"
        } else {
            Write-Result -Label $h.Host -Status 'WARN' -Detail "TLS OK but issuer '$issuer' is unusual - TLS inspection proxy?"
        }
        $ssl.Close(); $tcp.Close()
    } catch {
        Write-Result -Label $h.Host -Status 'FAIL' -Detail $_.Exception.Message
    }
}

# --- 4. HTTPS reachability -------------------------------------------------

Section '4. HTTPS GET (does the API respond?)'
foreach ($h in $hostsToTest) {
    try {
        $req = [System.Net.HttpWebRequest]::Create("https://$($h.Host)/")
        $req.Method    = 'GET'
        $req.Timeout   = 8000
        $req.UserAgent = 'ScreenRecordingUploadTest/1.0'
        try {
            $resp = $req.GetResponse()
            $code = [int]$resp.StatusCode
            $resp.Close()
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) {
                $code = [int]$_.Exception.Response.StatusCode
            } else { throw }
        }
        Write-Result -Label $h.Host -Status 'PASS' -Detail "HTTP $code"
    } catch {
        Write-Result -Label $h.Host -Status 'FAIL' -Detail $_.Exception.Message
    }
}

# --- 5. Upload endpoint: unauthenticated PUT ------------------------------

Section "5. Upload PUT probe -> api-$BandId.total.care"
$probeUrl = "https://api-$BandId.total.care/Apps/FileMassStorage/00000000-0000-0000-0000-000000000000/ScreenRecordings/upload-test-probe.mp4?metaDataType=VideoMp4&isBinary=true&ttlSeconds=60"
try {
    $req = [System.Net.HttpWebRequest]::Create($probeUrl)
    $req.Method        = 'PUT'
    $req.ContentType   = 'application/octet-stream'
    $req.Timeout       = 10000
    $req.UserAgent     = 'ScreenRecordingUploadTest/1.0'
    $body              = [byte[]](0x00,0x00,0x00,0x00)
    $req.ContentLength = $body.Length
    $s = $req.GetRequestStream(); $s.Write($body, 0, $body.Length); $s.Close()

    $server = ''
    $ctype  = ''
    try {
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $code   = [int]$_.Exception.Response.StatusCode
            $server = $_.Exception.Response.Headers['Server']
            $ctype  = $_.Exception.Response.ContentType
        } else { throw }
    }
    switch ($code) {
        401 { Write-Result -Label 'PUT probe' -Status 'PASS' -Detail 'HTTP 401 - path reachable, auth required (this is the expected healthy result)' }
        403 { Write-Result -Label 'PUT probe' -Status 'WARN' -Detail "HTTP 403 - could be normal, or a proxy block page. Server: $server, CT: $ctype" }
        404 { Write-Result -Label 'PUT probe' -Status 'WARN' -Detail 'HTTP 404 - reachable but path unknown (API may have changed)' }
        { $_ -ge 500 } { Write-Result -Label 'PUT probe' -Status 'WARN' -Detail "HTTP $code - server or proxy error" }
        default        { Write-Result -Label 'PUT probe' -Status 'PASS' -Detail "HTTP $code (reachable)" }
    }
} catch {
    Write-Result -Label 'PUT probe' -Status 'FAIL' -Detail "$($_.Exception.Message)  <-- firewall likely blocking outbound PUT / long-lived HTTPS to this host"
}

# --- 6. WebSocket upgrade (SignalR control channel) ------------------------

Section "6. WebSocket (WSS) upgrade -> api-$BandId.total.care"
try {
    $tcp = New-Object System.Net.Sockets.TcpClient("api-$BandId.total.care", 443)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
    $tlsProtos = [System.Security.Authentication.SslProtocols]::Tls12
    try { $tlsProtos = $tlsProtos -bor [System.Security.Authentication.SslProtocols]::Tls13 } catch { }
    $ssl.AuthenticateAsClient("api-$BandId.total.care", $null, $tlsProtos, $false)

    $key = [Convert]::ToBase64String([byte[]](1..16 | ForEach-Object { Get-Random -Max 256 }))
    $req = @(
        "GET /signalr/negotiate HTTP/1.1",
        "Host: api-$BandId.total.care",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: $key",
        "Sec-WebSocket-Version: 13",
        "User-Agent: ScreenRecordingUploadTest/1.0",
        "", ""
    ) -join "`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
    $ssl.Write($bytes, 0, $bytes.Length); $ssl.Flush()

    $buf = New-Object byte[] 4096
    $tcp.ReceiveTimeout = 6000
    $n = $ssl.Read($buf, 0, $buf.Length)
    $reply  = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
    $status = ($reply -split "`r`n")[0]
    if ($reply -match '^HTTP/\d\.\d\s+(101|401|404)') {
        Write-Result -Label 'WSS upgrade' -Status 'PASS' -Detail $status
    } elseif ($reply -match '^HTTP/\d\.\d\s+400') {
        Write-Result -Label 'WSS upgrade' -Status 'WARN' -Detail "$status - server rejected but reachable"
    } else {
        Write-Result -Label 'WSS upgrade' -Status 'WARN' -Detail "$status - proxy may be stripping WebSocket Upgrade header"
    }
    $ssl.Close(); $tcp.Close()
} catch {
    Write-Result -Label 'WSS upgrade' -Status 'FAIL' -Detail $_.Exception.Message
}

# --- 7. Local state --------------------------------------------------------

Section '7. Local recording queue'
$recDir   = Join-Path $env:APPDATA 'Screen Recording\Recordings'
$attempts = Join-Path $env:APPDATA 'Screen Recording\uploadAttempts.json'
if (Test-Path $recDir) {
    $mp4  = @(Get-ChildItem $recDir -Filter *.mp4  -ErrorAction SilentlyContinue)
    $json = @(Get-ChildItem $recDir -Filter *.json -ErrorAction SilentlyContinue)
    Write-Result -Label "Recordings folder: $recDir" -Status 'INFO' -Detail "$($mp4.Count) mp4 file(s), $($json.Count) json sidecar(s) pending"
} else {
    Write-Result -Label 'Recordings folder' -Status 'INFO' -Detail 'not present yet (app has not recorded anything)'
}
if (Test-Path $attempts) {
    try {
        $ua = Get-Content $attempts -Raw | ConvertFrom-Json
        if ($ua.Count -gt 0) {
            Write-Result -Label 'Prior upload failures (uploadAttempts.json)' -Status 'WARN' -Detail "$($ua.Count) failed attempt record(s) on disk"
            $ua | Select-Object -First 3 | ForEach-Object {
                $ln = "         - {0}  errorType={1}" -f $_.filepath, $_.errorType
                Write-Host $ln -ForegroundColor DarkGray
                try { Add-Content -LiteralPath $script:LogPath -Value $ln -Encoding UTF8 } catch { }
            }
        } else {
            Write-Result -Label 'Prior upload failures' -Status 'PASS' -Detail 'none recorded'
        }
    } catch {
        Write-Result -Label 'uploadAttempts.json' -Status 'WARN' -Detail 'file present but unparseable'
    }
}

# --- 8. App state ---------------------------------------------------------

Section '8. App state'
$appExe = Join-Path $env:LOCALAPPDATA 'Programs\screenrecording\Screen Recording.exe'
if (Test-Path $appExe) {
    try {
        $vi = (Get-Item $appExe).VersionInfo
        Write-Result -Label 'Installed' -Status 'PASS' -Detail "$appExe  (v$($vi.ProductVersion))"
    } catch {
        Write-Result -Label 'Installed' -Status 'PASS' -Detail $appExe
    }
} else {
    Write-Result -Label 'Installed' -Status 'FAIL' -Detail "Not found at $appExe"
}
$procs = @(Get-Process -Name 'Screen Recording' -ErrorAction SilentlyContinue)
if ($procs.Count -gt 0) {
    $started = ($procs | Sort-Object StartTime | Select-Object -First 1).StartTime
    Write-Result -Label 'Running' -Status 'PASS' -Detail "$($procs.Count) process(es), started $started"
} else {
    Write-Result -Label 'Running' -Status 'WARN' -Detail 'Not currently running - launch it before recording is expected'
}
# Autostart: HKCU Run key or Startup folder
$autostart = $null
try {
    $rk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $v  = (Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue).PSObject.Properties |
          Where-Object { $_.Value -and $_.Value -match 'screenrecording|Screen Recording' }
    if ($v) { $autostart = "HKCU Run\$($v.Name)" }
} catch { }
if (-not $autostart) {
    $startup = [Environment]::GetFolderPath('Startup')
    $lnk = Get-ChildItem -Path $startup -Filter '*Screen Recording*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($lnk) { $autostart = $lnk.FullName }
}
if ($autostart) {
    Write-Result -Label 'Autostart at logon' -Status 'PASS' -Detail $autostart
} else {
    Write-Result -Label 'Autostart at logon' -Status 'WARN' -Detail 'No Run-key or Startup-folder entry found - agent will not launch at logon'
}

# --- 9. Local data health -------------------------------------------------

Section '9. Local data health'
$recDir = Join-Path $env:APPDATA 'Screen Recording\Recordings'
if (Test-Path $recDir) {
    $allMp4 = @(Get-ChildItem $recDir -Filter *.mp4 -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime)
    if ($allMp4.Count -eq 0) {
        Write-Result -Label 'Backlog age' -Status 'PASS' -Detail 'No pending recordings'
    } else {
        $oldest    = $allMp4[0]
        $ageHours  = [math]::Round(((Get-Date) - $oldest.LastWriteTime).TotalHours, 1)
        $totalMB   = [math]::Round((( $allMp4 | Measure-Object Length -Sum).Sum) / 1MB, 1)
        if ($ageHours -gt 48) {
            Write-Result -Label 'Backlog age' -Status 'FAIL' -Detail "$($allMp4.Count) mp4(s), $totalMB MB total, oldest is $ageHours h old - uploads are stalled"
        } elseif ($ageHours -gt 4) {
            Write-Result -Label 'Backlog age' -Status 'WARN' -Detail "$($allMp4.Count) mp4(s), $totalMB MB total, oldest is $ageHours h old"
        } else {
            Write-Result -Label 'Backlog age' -Status 'PASS' -Detail "$($allMp4.Count) mp4(s), $totalMB MB total, oldest is $ageHours h old"
        }
    }
    # Disk free
    try {
        $drive = (Get-Item $recDir).PSDrive
        $freeGB = [math]::Round($drive.Free / 1GB, 1)
        if ($freeGB -lt 2) {
            Write-Result -Label 'Disk free' -Status 'FAIL' -Detail "$freeGB GB free on $($drive.Name): - recordings will fail to write"
        } elseif ($freeGB -lt 10) {
            Write-Result -Label 'Disk free' -Status 'WARN' -Detail "$freeGB GB free on $($drive.Name):"
        } else {
            Write-Result -Label 'Disk free' -Status 'PASS' -Detail "$freeGB GB free on $($drive.Name):"
        }
    } catch {
        Write-Result -Label 'Disk free' -Status 'WARN' -Detail $_.Exception.Message
    }
} else {
    Write-Result -Label 'Recordings folder' -Status 'INFO' -Detail 'not present yet'
}
# failedUploadsFolder (from screenRecordingSettings) - default under Recordings\failed
$failedDir = Join-Path $recDir 'failed'
if (Test-Path $failedDir) {
    $fCount = (Get-ChildItem $failedDir -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($fCount -gt 0) {
        Write-Result -Label 'Permanently failed uploads folder' -Status 'WARN' -Detail "$fCount file(s) in $failedDir"
    }
}
# Log errors in last 24h
$mainLog     = Join-Path $env:APPDATA 'Screen Recording\logs\main.log'
$rendererLog = Join-Path $env:APPDATA 'Screen Recording\logs\renderer.log'
foreach ($lf in @($mainLog, $rendererLog)) {
    if (-not (Test-Path $lf)) { continue }
    try {
        # Last 800 lines is enough for 24h on this app's volume
        $tail = Get-Content $lf -Tail 800 -ErrorAction SilentlyContinue
        $errs = @($tail | Where-Object { $_ -match '\[error\]|Failed|SSPI failed|Attempting reconnect|SignalR failed|Could not get startup lock' })
        $label = "Recent errors in $($lf | Split-Path -Leaf)"
        if ($errs.Count -eq 0) {
            Write-Result -Label $label -Status 'PASS' -Detail 'none in the last ~800 lines'
        } else {
            Write-Result -Label $label -Status 'WARN' -Detail "$($errs.Count) error line(s) - showing 3 most recent:"
            $errs | Select-Object -Last 3 | ForEach-Object {
                $ln = "         - " + ($_ -replace '\s+', ' ').Trim()
                if ($ln.Length -gt 180) { $ln = $ln.Substring(0,180) + '...' }
                Write-Host $ln -ForegroundColor DarkGray
                try { Add-Content -LiteralPath $script:LogPath -Value $ln -Encoding UTF8 } catch { }
            }
        }
    } catch {
        Write-Result -Label $lf -Status 'WARN' -Detail $_.Exception.Message
    }
}

# --- 10. Network extras ---------------------------------------------------

Section '10. Network extras'
# RTT to the band-specific upload host
try {
    $ping = Test-Connection -ComputerName "api-$BandId.total.care" -Count 4 -ErrorAction Stop
    $avg  = [math]::Round(($ping | Measure-Object ResponseTime -Average).Average, 0)
    $lost = 4 - $ping.Count
    if ($lost -gt 0) {
        Write-Result -Label "RTT to api-$BandId.total.care" -Status 'WARN' -Detail "avg ${avg}ms, $lost/4 packets lost"
    } elseif ($avg -gt 250) {
        Write-Result -Label "RTT to api-$BandId.total.care" -Status 'WARN' -Detail "avg ${avg}ms (high - large uploads may time out)"
    } else {
        Write-Result -Label "RTT to api-$BandId.total.care" -Status 'PASS' -Detail "avg ${avg}ms, 0 packet loss"
    }
} catch {
    Write-Result -Label "RTT to api-$BandId.total.care" -Status 'WARN' -Detail 'ICMP blocked (common on corp networks - not a real problem)'
}
# Cert expiry for the upload host (captured in section 3)
if ($script:CertExpiry -and $script:CertExpiry.ContainsKey("api-$BandId.total.care")) {
    $exp = $script:CertExpiry["api-$BandId.total.care"]
    $daysLeft = [math]::Round(($exp - (Get-Date)).TotalDays, 0)
    if ($daysLeft -lt 0) {
        Write-Result -Label 'Server cert expiry' -Status 'FAIL' -Detail "EXPIRED $([math]::Abs($daysLeft)) day(s) ago ($exp)"
    } elseif ($daysLeft -lt 30) {
        Write-Result -Label 'Server cert expiry' -Status 'WARN' -Detail "$daysLeft days left ($exp)"
    } else {
        Write-Result -Label 'Server cert expiry' -Status 'PASS' -Detail "$daysLeft days left ($exp)"
    }
}
# Updater feed reachable
$updateUrl = 'https://portal.total.care/Downloads/ScreenRecording/Windows/latest.yml'
try {
    $req = [System.Net.HttpWebRequest]::Create($updateUrl)
    $req.Method    = 'GET'
    $req.Timeout   = 8000
    $req.UserAgent = 'ScreenRecordingUploadTest/1.0'
    $resp = $req.GetResponse()
    $code = [int]$resp.StatusCode
    $len  = $resp.ContentLength
    $resp.Close()
    if ($code -eq 200 -and $len -gt 0) {
        Write-Result -Label 'Updater feed (latest.yml)' -Status 'PASS' -Detail "HTTP $code, $len bytes"
    } else {
        Write-Result -Label 'Updater feed (latest.yml)' -Status 'WARN' -Detail "HTTP $code, $len bytes"
    }
} catch {
    Write-Result -Label 'Updater feed (latest.yml)' -Status 'WARN' -Detail $_.Exception.Message
}
# Windows Internet Settings proxy
try {
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) {
        Write-Result -Label 'Windows proxy' -Status 'WARN' -Detail "Configured: $($ie.ProxyServer) - the app may route through this (Electron respects it)"
    } else {
        Write-Result -Label 'Windows proxy' -Status 'PASS' -Detail 'None configured'
    }
    if ($ie.AutoConfigURL) {
        Write-Result -Label 'PAC file (WPAD)' -Status 'INFO' -Detail $ie.AutoConfigURL
    }
} catch {
    Write-Result -Label 'Windows proxy' -Status 'WARN' -Detail $_.Exception.Message
}

# --- 11. System sanity ----------------------------------------------------

Section '11. System sanity'
# Clock skew via HTTP Date header (works even when NTP is blocked)
try {
    $req = [System.Net.HttpWebRequest]::Create('https://api-' + $BandId + '.total.care/')
    $req.Method    = 'HEAD'
    $req.Timeout   = 5000
    $req.UserAgent = 'ScreenRecordingUploadTest/1.0'
    $t0 = Get-Date
    try { $resp = $req.GetResponse(); $dh = $resp.Headers['Date']; $resp.Close() }
    catch [System.Net.WebException] { if ($_.Exception.Response) { $dh = $_.Exception.Response.Headers['Date']; $_.Exception.Response.Close() } else { throw } }
    if ($dh) {
        $serverTime = [DateTime]::Parse($dh).ToUniversalTime()
        $localUtc   = $t0.ToUniversalTime()
        $skewSec    = [math]::Round(($localUtc - $serverTime).TotalSeconds, 0)
        $absSkew    = [math]::Abs($skewSec)
        if ($absSkew -gt 300) {
            Write-Result -Label 'System clock skew' -Status 'FAIL' -Detail "$skewSec seconds off server - bearer tokens will be rejected. Fix Windows time sync"
        } elseif ($absSkew -gt 60) {
            Write-Result -Label 'System clock skew' -Status 'WARN' -Detail "$skewSec seconds off server"
        } else {
            Write-Result -Label 'System clock skew' -Status 'PASS' -Detail "$skewSec seconds off server (within tolerance)"
        }
    } else {
        Write-Result -Label 'System clock skew' -Status 'WARN' -Detail 'No Date header returned'
    }
} catch {
    Write-Result -Label 'System clock skew' -Status 'WARN' -Detail $_.Exception.Message
}
# Session freshness (userConfig.json age)
$userCfg = Join-Path $env:APPDATA 'Screen Recording\userConfig.json'
if (Test-Path $userCfg) {
    $mtime  = (Get-Item $userCfg).LastWriteTime
    $ageDays = [math]::Round(((Get-Date) - $mtime).TotalDays, 1)
    if ($ageDays -gt 60) {
        Write-Result -Label 'Session file (userConfig.json)' -Status 'WARN' -Detail "Last updated $ageDays days ago - session may be stale, log back in"
    } else {
        Write-Result -Label 'Session file (userConfig.json)' -Status 'PASS' -Detail "Last updated $ageDays day(s) ago"
    }
} else {
    Write-Result -Label 'Session file (userConfig.json)' -Status 'FAIL' -Detail 'Missing - user is not signed in to Screen Recording'
}

# --- interpretation guide --------------------------------------------------

Log ''
Log 'Interpreting the results' 'Cyan'
Log '  * Every row PASS  -> firewall is not the problem. If uploads still fail, the'
Log '                       cause is auth/session (log out and back in via the portal).'
Log '  * FAIL on the api-*.total.care rows in DNS/TCP/HTTPS -> firewall or DNS'
Log '                       filter is blocking that specific host. Ask netops to allow'
Log '                       *.total.care and *.callcorp.com outbound on 443.'
Log "  * WARN on TLS with an unusual issuer (e.g. 'FortiGate', 'ZScaler',"
Log "                       'Palo Alto', 'Cisco Umbrella') -> TLS inspection is"
Log '                       terminating the connection. That will break the SignalR'
Log '                       upgrade and can break large PUTs. Ask netops to add'
Log '                       *.total.care and *.callcorp.com to the SSL bypass list.'
Log '  * FAIL on the PUT probe but PASS on HTTPS GET -> outbound HTTP PUT or long-'
Log '                       lived requests are being blocked. Look for an app-'
Log '                       aware firewall rule (SonicWall/Palo Alto DPI) that'
Log '                       drops non-GET/POST verbs.'
Log '  * FAIL on WSS upgrade -> proxy is stripping the Upgrade header. The app'
Log '                       will fall back to long-polling but push commands'
Log '                       (like StartUploadingScreenRecordings) become slow.'
Log ''
Log $sep 'DarkCyan'
Log ("END OF RUN     {0} UTC" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) 'White'
Log $sep 'DarkCyan'
Log ''
Log ("Full log appended to: {0}" -f $script:LogPath) 'Green'
Log ''

# --- pause so double-clicked exe doesn't slam shut -------------------------

if (-not $NoPause) {
    Write-Host 'Press any key to close...' -ForegroundColor DarkGray
    try {
        [void][System.Console]::ReadKey($true)
    } catch {
        # No interactive console (e.g. redirected) - just exit.
    }
}
