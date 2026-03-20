using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace SharpWinRM.Commands
{
    internal class Exec
    {
        internal static void Run(ArgumentParser args, WinRmContext ctx)
        {
            string command = args.Get("command");
            if (string.IsNullOrEmpty(command))
            {
                Helpers.PrintError("Missing /command:");
                return;
            }

            Helpers.PrintInfo("Target  : " + ctx.Url);
            Helpers.PrintInfo("User    : " + ctx.DisplayUser);
            Helpers.PrintInfo("Auth    : " + ctx.Auth);
            Helpers.PrintInfo("Command : " + command);
            Console.WriteLine();

            try
            {
                if (ctx.Auth == AuthMode.Ticket)
                {
                    Helpers.PrintInfo("Creating isolated logon session...");
                    using (KerberosTicket.CreateAndImport(ctx.Ticket))
                    {
                        Helpers.PrintSuccess("Ticket loaded (isolated session — your session is untouched).");
                        Console.WriteLine();
                        DoPsrp(ctx, command);
                    }
                }
                else
                {
                    DoPsrp(ctx, command);
                }
            }
            catch (Exception ex)
            {
                Helpers.PrintError("Exec failed: " + ex.Message);
            }
        }

        private static void DoPsrp(WinRmContext ctx, string command)
        {
            // Executes via the PowerShell Remoting Protocol (PSRP) endpoint rather than
            // the WinRM cmd shell.  Remote process tree:
            //
            //   svchost.exe (WsmSvc) → wsmprovhost.exe
            //
            // No cmd.exe, no powershell.exe child — the PS engine runs in-process inside
            // wsmprovhost.exe, identical to legitimate Invoke-Command / Enter-PSSession.
            // The command never appears in any process command line or Sysmon Event ID 1.
            PSCredential credential = null;
            if (ctx.Auth == AuthMode.Password)
            {
                var secure = new SecureString();
                foreach (char c in ctx.Password) secure.AppendChar(c);
                credential = new PSCredential(ctx.DisplayUser, secure);
            }

            var connInfo = new WSManConnectionInfo(
                new Uri(ctx.Url),
                "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
                credential);

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

            using (var runspace = RunspaceFactory.CreateRunspace(connInfo))
            {
                runspace.Open();

                using (var ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;
                    ps.AddScript(command).AddCommand("Out-String").AddParameter("Width", 4096);

                    var results = ps.Invoke<string>();

                    foreach (var e in ps.Streams.Error)
                        Helpers.PrintWarn("[error] " + e);

                    bool hasOutput = false;
                    foreach (string s in results)
                    {
                        if (string.IsNullOrWhiteSpace(s)) continue;
                        string[] lines = s.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
                        foreach (string line in lines)
                        {
                            string trimmed = line.TrimEnd();
                            if (string.IsNullOrEmpty(trimmed)) continue;
                            Console.WriteLine(trimmed);
                            hasOutput = true;
                        }
                    }

                    if (!hasOutput && ps.Streams.Error.Count == 0)
                        Helpers.PrintWarn("(no output)");
                }
            }
        }
    }
}
