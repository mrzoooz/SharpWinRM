using System;
using System.IO;

namespace SharpWinRM.Commands
{
    internal class Download
    {
        internal static void Run(ArgumentParser args, WinRmContext ctx)
        {
            string remote = args.Get("remote");
            string local  = args.Get("local");

            if (string.IsNullOrEmpty(remote)) { Helpers.PrintError("Missing /remote:"); return; }
            if (string.IsNullOrEmpty(local))  { Helpers.PrintError("Missing /local:");  return; }

            Helpers.PrintInfo("Target  : " + ctx.Url);
            Helpers.PrintInfo("Auth    : " + ctx.Auth);
            Helpers.PrintInfo("Remote  : " + remote);
            Helpers.PrintInfo("Local   : " + local);
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
                        DoDownload(ctx, remote, local);
                    }
                }
                else
                {
                    DoDownload(ctx, remote, local);
                }
            }
            catch (Exception ex)
            {
                Helpers.PrintError("Download failed: " + ex.Message);
            }
        }

        private static void DoDownload(WinRmContext ctx, string remote, string local)
        {
            // Use cmd.exe's built-in type command — no PowerShell spawned at all.
            // Raw bytes travel through the WinRM stdout pipe, base64-encoded by the
            // protocol, and decoded back to the original bytes on this side.
            // Process visible to EDR: cmd.exe /c type "remote_path"  (path only, no data)
            //
            // Note: type reads through a pipe in binary mode on modern Windows, so
            // this is safe for most files. Avoid for binaries containing 0x1A bytes
            // (rare but possible in PE files) — use SMB for those cases.
            Helpers.PrintInfo("Downloading...");
            using (var client = WsManClient.Create(ctx))
            {
                byte[] data = client.RunCommandBytes("type \"" + remote + "\"");

                if (data.Length == 0)
                    throw new Exception("No data received — verify path and permissions.");

                string dir = Path.GetDirectoryName(Path.GetFullPath(local));
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllBytes(local, data);
                Helpers.PrintSuccess("Downloaded " + data.Length + " bytes → " + local);
            }
        }
    }
}
