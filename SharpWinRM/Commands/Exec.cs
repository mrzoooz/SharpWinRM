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
                    // Import ticket into an isolated logon session (no trace in our session).
                    // Keep impersonation alive across the WsManClient call so SSPI picks up
                    // the Kerberos ticket from the sacrificial session.
                    Helpers.PrintInfo("Creating isolated logon session...");
                    using (KerberosTicket.CreateAndImport(ctx.Ticket))
                    {
                        Helpers.PrintSuccess("Ticket loaded (isolated session — your session is untouched).");
                        Console.WriteLine();
                        RunWithWsMan(ctx, command);
                    }
                }
                else
                {
                    RunWithWsMan(ctx, command);
                }
            }
            catch (Exception ex)
            {
                Helpers.PrintError("Exec failed: " + ex.Message);
            }
        }

        private static void RunWithWsMan(WinRmContext ctx, string command)
        {
            using (var client = WsManClient.Create(ctx))
                PrintOutput(client.RunCommand(command));
        }

        private static void PrintOutput(string output)
        {
            if (!string.IsNullOrWhiteSpace(output))
                Console.Write(output);
            else
                Helpers.PrintWarn("(no output)");
        }
    }
}
