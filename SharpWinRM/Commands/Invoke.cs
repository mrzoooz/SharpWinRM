using System;
using System.Text;

namespace SharpWinRM.Commands
{
    internal class Invoke
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
                        DoInvoke(ctx, command);
                    }
                }
                else
                {
                    DoInvoke(ctx, command);
                }
            }
            catch (Exception ex)
            {
                Helpers.PrintError("Invoke failed: " + ex.Message);
            }
        }

        private static void DoInvoke(WinRmContext ctx, string command)
        {
            // Send the command through the WinRM stdin channel to a PowerShell process
            // started with no arguments.  The process creation event logged by Sysmon/EDR
            // shows only:  powershell.exe -NoProfile -NonInteractive -
            // The actual command content travels through stdin — never visible in any
            // process command line or Sysmon Event ID 1.
            //
            // Note: AMSI still inspects the script block at runtime, and PowerShell
            // Script Block Logging (if enabled) will capture it in the event log.
            string script = command + "\r\nexit\r\n";
            byte[] stdinBytes = Encoding.UTF8.GetBytes(script);

            using (var client = WsManClient.Create(ctx))
            {
                string output = client.RunWithStdin(
                    "powershell.exe",
                    "-NoProfile -NonInteractive -",
                    stdinBytes);

                if (!string.IsNullOrWhiteSpace(output))
                    Console.Write(output);
                else
                    Helpers.PrintWarn("(no output)");
            }
        }
    }
}
