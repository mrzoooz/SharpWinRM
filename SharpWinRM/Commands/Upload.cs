using System;
using System.IO;
using System.Text;

namespace SharpWinRM.Commands
{
    internal class Upload
    {
        internal static void Run(ArgumentParser args, WinRmContext ctx)
        {
            string local  = args.Get("local");
            string remote = args.Get("remote");

            if (string.IsNullOrEmpty(local))  { Helpers.PrintError("Missing /local:");  return; }
            if (string.IsNullOrEmpty(remote)) { Helpers.PrintError("Missing /remote:"); return; }
            if (!File.Exists(local))          { Helpers.PrintError("File not found: " + local); return; }

            Helpers.PrintInfo("Target  : " + ctx.Url);
            Helpers.PrintInfo("Auth    : " + ctx.Auth);
            Helpers.PrintInfo("Local   : " + local);
            Helpers.PrintInfo("Remote  : " + remote);
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
                        DoUpload(ctx, local, remote);
                    }
                }
                else
                {
                    DoUpload(ctx, local, remote);
                }
            }
            catch (Exception ex)
            {
                Helpers.PrintError("Upload failed: " + ex.Message);
            }
        }

        private static void DoUpload(WinRmContext ctx, string local, string remote)
        {
            // If remote looks like a directory (ends with \ or has no extension),
            // append the local filename automatically.
            if (remote.EndsWith("\\") ||
                string.IsNullOrEmpty(Path.GetExtension(remote)))
                remote = remote.TrimEnd('\\') + "\\" + Path.GetFileName(local);

            byte[] fileBytes = File.ReadAllBytes(local);
            Helpers.PrintInfo("Uploading " + fileBytes.Length + " bytes...");

            // Build a PowerShell script that writes the file on the remote host.
            // The script is delivered via the WinRM stdin channel — file data never
            // appears in any process command line (not logged by Sysmon EventID 1).
            //
            // Remote process created: powershell.exe -NoProfile -NonInteractive -
            // (minimal, opaque command line; script arrives through stdin)
            //
            // 48 KB binary chunks → ~64 KB base64 per PS statement, well under
            // the WinRM default MaxEnvelopeSize of 153 600 bytes per Send message.
            const int chunkSize = 48 * 1024;
            var script = new StringBuilder();
            script.AppendLine("$s=[IO.File]::OpenWrite('" + remote + "')");
            script.AppendLine("$s.SetLength(0)");
            for (int off = 0; off < fileBytes.Length; off += chunkSize)
            {
                int    len   = Math.Min(chunkSize, fileBytes.Length - off);
                byte[] chunk = new byte[len];
                Array.Copy(fileBytes, off, chunk, 0, len);
                script.AppendLine("[byte[]]$c=[Convert]::FromBase64String('" +
                    Convert.ToBase64String(chunk) + "')");
                script.AppendLine("$s.Write($c,0,$c.Length)");
            }
            script.AppendLine("$s.Flush()");
            script.AppendLine("$s.Close()");

            byte[] stdinBytes = Encoding.UTF8.GetBytes(script.ToString());

            using (var client = WsManClient.Create(ctx))
            {
                string output = client.RunWithStdin(
                    "powershell.exe",
                    "-NoProfile -NonInteractive -",
                    stdinBytes);

                if (!string.IsNullOrWhiteSpace(output))
                    Helpers.PrintWarn("Remote output: " + output.Trim());
            }

            Helpers.PrintSuccess("Uploaded " + fileBytes.Length + " bytes → " + remote);
        }
    }
}
