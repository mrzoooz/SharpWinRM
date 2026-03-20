using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace SharpWinRM
{
    /// <summary>
    /// Shared PSRP connection helper.
    /// Opens a runspace to the Microsoft.PowerShell endpoint — PS engine runs
    /// in-process inside wsmprovhost.exe with no child process spawned.
    /// Remote process tree: svchost (WsmSvc) → wsmprovhost.exe
    /// </summary>
    internal class PsrpClient : IDisposable
    {
        private readonly Runspace _runspace;

        internal static PsrpClient Connect(WinRmContext ctx)
        {
            PSCredential cred = null;
            if (ctx.Auth == AuthMode.Password)
            {
                var secure = new SecureString();
                foreach (char c in ctx.Password) secure.AppendChar(c);
                cred = new PSCredential(ctx.DisplayUser, secure);
            }

            var connInfo = new WSManConnectionInfo(
                new Uri(ctx.Url),
                "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
                cred);

            connInfo.AuthenticationMechanism = (ctx.Auth == AuthMode.Ptt || ctx.Auth == AuthMode.Ticket)
                ? AuthenticationMechanism.Kerberos
                : AuthenticationMechanism.Negotiate;

            if (ctx.Ssl)
            {
                connInfo.SkipCACheck         = true;
                connInfo.SkipCNCheck         = true;
                connInfo.SkipRevocationCheck = true;
            }

            connInfo.OpenTimeout      = ctx.TimeoutMs;
            connInfo.OperationTimeout = ctx.TimeoutMs;

            var rs = RunspaceFactory.CreateRunspace(connInfo);
            rs.Open();
            return new PsrpClient(rs);
        }

        private PsrpClient(Runspace rs) { _runspace = rs; }

        // Run a script and return formatted text output (piped through Out-String).
        // Use for display — complex objects render as tables/lists.
        internal System.Collections.ObjectModel.Collection<string> RunFormatted(string script)
        {
            using (var ps = PowerShell.Create())
            {
                ps.Runspace = _runspace;
                ps.AddScript(script).AddCommand("Out-String").AddParameter("Width", 4096);
                var results = ps.Invoke<string>();
                foreach (var e in ps.Streams.Error)
                    Helpers.PrintWarn("[error] " + e);
                return results;
            }
        }

        // Run a script and return the raw first string result.
        // Use for scripts that return a single string value (e.g. base64 data).
        internal string RunRaw(string script)
        {
            using (var ps = PowerShell.Create())
            {
                ps.Runspace = _runspace;
                ps.AddScript(script);
                var results = ps.Invoke<string>();
                if (ps.Streams.Error.Count > 0)
                    throw new Exception(ps.Streams.Error[0].ToString());
                return results.Count > 0 ? results[0] : string.Empty;
            }
        }

        // Run a script with no expected output. Throws on remote errors.
        internal void RunVoid(string script)
        {
            using (var ps = PowerShell.Create())
            {
                ps.Runspace = _runspace;
                ps.AddScript(script);
                ps.Invoke();
                if (ps.Streams.Error.Count > 0)
                    throw new Exception(ps.Streams.Error[0].ToString());
            }
        }

        public void Dispose() { try { _runspace?.Dispose(); } catch { } }
    }
}
