using System;

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
            // Executes via the PowerShell Remoting Protocol (PSRP).
            // PS engine runs in-process inside wsmprovhost.exe — no child process.
            // Remote process tree: svchost (WsmSvc) → wsmprovhost.exe (no children)
            using (var psrp = PsrpClient.Connect(ctx))
            {
                var results = psrp.RunFormatted(command);

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

                if (!hasOutput)
                    Helpers.PrintWarn("(no output)");
            }
        }
    }
}
