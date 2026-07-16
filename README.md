<!-- V26.197.1700 - README.md -->
<p align="right">
  <img alt="version" src="https://img.shields.io/badge/version-V26.197.1700-blue">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="platform" src="https://img.shields.io/badge/platform-Windows-lightgrey">
</p>

# ScreenRecording-UploadTest

A Windows diagnostic that answers one question: **can this workstation upload recordings from the CallCorp "Screen Recording" desktop app?**

If uploads are silently failing, it's almost never the app - it's the workstation, the network, or the session. This tool exercises the exact endpoints and code paths the app uses (traced from its Electron `app.asar`) and writes a plain-text report you can attach to a ticket.

- No credentials sent, no data collected, no user prompts.
- Single self-contained `.exe` (~54 KB). No install, no dependencies beyond Windows PowerShell 5.1.
- Appends each run as a timestamped block to `CXsyncScreenRecording.txt` next to the exe.

---

## What it checks

The tool runs 11 sections and marks each row `PASS` / `WARN` / `FAIL` / `INFO`.

| # | Section | Detects |
|---|---|---|
| 1 | DNS resolution | Blocked DNS / hijacked hostname for the four hosts the app uses (`portal.total.care`, `api.callcorp.com`, `api.total.care`, `api-<band>.total.care`) |
| 2 | TCP 443 reachability | Firewall dropping outbound 443 |
| 3 | TLS handshake + issuer | TLS-inspection proxy in the middle (issuer isn't a known public CA) |
| 4 | HTTPS GET | Any HTTP response confirms the pipe works end-to-end |
| 5 | Unauthenticated PUT probe | Firewall or DPI dropping `PUT` verb / long HTTPS bodies. Sent to the exact `Apps/FileMassStorage/{ownerId}/ScreenRecordings/…?metaDataType=VideoMp4` URL shape the app uses. `401` is the healthy result. |
| 6 | WebSocket (WSS) upgrade | Proxy stripping the `Upgrade` header (kills the SignalR command channel that triggers uploads) |
| 7 | Local recording queue | Pending `.mp4`/`.json` files, prior upload failures logged in `uploadAttempts.json` |
| 8 | App state | Installed path + version, currently running processes, autostart entry at logon |
| 9 | Local data health | Backlog age (`FAIL` if >48h), disk free, failed-uploads folder, recent error lines from `main.log` + `renderer.log` |
| 10 | Network extras | Round-trip latency to `api-<band>`, TLS cert expiry (`WARN` <30 days), updater feed reachable, Windows proxy / PAC file configured |
| 11 | System sanity | System clock skew vs. server (`FAIL` if >5 min - silently invalidates bearer tokens), age of `userConfig.json` (stale session) |

The bottom of each report includes a decoded interpretation guide: what each failure pattern means and the specific netops ask needed to resolve it.

---

## Usage

**Interactive** - double-click `ScreenRecording-UploadTest.exe`. A console window opens, results scroll by with color, and the window waits for a key before closing.

**Scripted / silent** - from cmd or PowerShell:

```powershell
.\ScreenRecording-UploadTest.exe -NoPause
```

**Force a specific band** if auto-detection can't find one in `renderer.log`:

```powershell
.\ScreenRecording-UploadTest.exe -BandId bnd3
```

### Output

The report streams to the console **and** appends to a plain-text log file:

```
<exe folder>\CXsyncScreenRecording.txt
```

If the exe folder isn't writable (e.g. `Program Files`), it falls back to `%LOCALAPPDATA%\CXsyncScreenRecording.txt`. Each run adds a full timestamped block - you get a rolling history.

---

## Deploying to an agent workstation

1. Copy `ScreenRecording-UploadTest.exe` to a writable folder on the workstation (Desktop, `C:\Temp`, wherever).
2. Have the user double-click it.
3. Ask for `CXsyncScreenRecording.txt` from that same folder.

That's the whole procedure. There's nothing to install and nothing to configure.

---

## Interpreting failures

| Failure pattern | Meaning | Fix |
|---|---|---|
| DNS/TCP/HTTPS **FAIL** on `api-*.total.care` | Firewall or DNS filter blocking the host | Ask netops to allow `*.total.care` and `*.callcorp.com` outbound on 443 |
| TLS **WARN** with unusual issuer (FortiGate, ZScaler, Palo Alto, Cisco Umbrella) | TLS inspection is terminating and re-signing the connection | Add `*.total.care` and `*.callcorp.com` to the SSL bypass list |
| PUT **FAIL** but HTTPS GET passes | App-aware firewall dropping non-GET/POST verbs | Allow HTTP `PUT` outbound for those hosts |
| WSS upgrade **FAIL** | Proxy stripping the `Upgrade` header | SignalR falls back to long-polling; push commands become slow |
| Backlog age **FAIL** with everything else green | Auth or session problem, not network | Log out and back in via [portal.total.care](https://portal.total.care) |
| Clock skew **FAIL** | Bearer tokens rejected as expired-before-issue | Fix Windows time sync (`w32tm /resync`) |
| Autostart **WARN** | App won't launch at logon on this workstation | Add a shortcut to the Startup folder or an HKCU `Run` entry |

---

## Building from source

Prerequisites: Windows PowerShell 5.1 (built into Windows 10/11) and the `ps2exe` module.

```powershell
Install-Module ps2exe -Scope CurrentUser -Force

Invoke-ps2exe `
  -inputFile   .\ScreenRecording-UploadTest.ps1 `
  -outputFile  .\ScreenRecording-UploadTest.exe `
  -title       'Screen Recording Upload Test' `
  -description 'Tests connectivity, local state, and system readiness for the CallCorp Screen Recording app' `
  -company     'CBTS' `
  -product     'ScreenRecording-UploadTest' `
  -version     '26.197.1630.0'
```

The compiled exe is unsigned. If SmartScreen flags it on first launch, choose *More info -> Run anyway*, or sign it with your own code-signing certificate.

---

## Privacy and safety

- The tool reads local config files (`recordingConfig.json`, `userConfig.json`, `logs\*.log`) to look up your `BandId` and to check session age.
- It **never** transmits your `access_token`, `apikey`, `ownerId`, or any local file content over the network.
- The PUT probe uses a hardcoded all-zero owner GUID (`00000000-0000-0000-0000-000000000000`) and a 4-byte body so the server rejects it as unauthorized (`401`) - which is exactly the outcome we want to prove reachability.

---

## Endpoints the CallCorp Screen Recording app uses

Documented here for netops allowlisting. All traffic is HTTPS on TCP 443; no other ports.

| Host | Purpose |
|---|---|
| `portal.total.care` | Login page + auto-updater download URL |
| `api.callcorp.com` | Bootstrap - `GET /Apps/Operations/LocationCodeInfo` returns the band |
| `api.total.care` | Fallback API host |
| `api-<band>.total.care` | Band-specific API - **upload target** and SignalR control channel. Common bands: `bnd1`, `bnd2`, `bnd3`. |

Upload requests are `PUT https://api-<band>.total.care/Apps/FileMassStorage/{ownerId}/ScreenRecordings/{fileName}` with `Content-Type: application/octet-stream` and a `Bearer` token. The recorder writes to `%APPDATA%\Screen Recording\Recordings\` and retries failed uploads on a 20-minute timer for up to a week.

---

## License

MIT - see [LICENSE](LICENSE). Copyright (c) 2026 Keith Talbot.

Not affiliated with, endorsed by, or supported by CallCorp or CBTS. "CallCorp" and "Screen Recording" are properties of their respective owners.
