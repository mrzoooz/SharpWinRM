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
            // Auto-complete remote path if a directory was specified.
            if (remote.EndsWith("\\") || string.IsNullOrEmpty(Path.GetExtension(remote)))
                remote = remote.TrimEnd('\\') + "\\" + Path.GetFileName(local);

            byte[] fileBytes = File.ReadAllBytes(local);
            Helpers.PrintInfo("Uploading " + fileBytes.Length + " bytes...");

            // ── How this works ────────────────────────────────────────────────────
            //
            // Step 1 — StdRegProv.CreateKey + SetStringValue (loop):
            //   Stages base64-encoded file chunks into a randomly named HKLM subkey.
            //   No child process — handled entirely inside wmiprvse.exe.
            //
            // Step 2 — Win32_Process.Create:
            //   Spawns a brief powershell.exe (parent: wmiprvse.exe) with a
            //   -EncodedCommand that reads the chunks from registry, writes the
            //   file to disk, then sets a "done" sentinel value.
            //   File data and path are NOT in plain-text process args.
            //
            // Step 3 — Win32_Process?Handle=<pid> (poll):
            //   Waits for the PS process to exit via WS-Man Get. No child process.
            //
            // Step 4 — StdRegProv.GetStringValue:
            //   Reads the "done" sentinel once after process exit to detect errors.
            //
            // Step 5 — StdRegProv.DeleteKey:
            //   Removes the staging key. No child process.
            //
            // Remote process tree:
            //   svchost (WinMgmt) → wmiprvse.exe → powershell.exe  (brief, step 2 only)
            //   All other steps: wmiprvse.exe only (no child process).
            // ─────────────────────────────────────────────────────────────────────

            const string parentKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Diagnostics";
            string stagingKey = parentKey + "\\WinUpd_" + Guid.NewGuid().ToString("N").Substring(0, 8);

            using (var client = WsManClient.Create(ctx))
            {
                // Step 1: Create staging key and write file chunks (no child process)
                Helpers.PrintInfo("Staging via StdRegProv (no child process)...");
                client.WmiRegCreateKey(stagingKey);

                const int chunkSize = 48 * 1024;
                int chunkCount = 0;
                for (int off = 0; off < fileBytes.Length; off += chunkSize, chunkCount++)
                {
                    int    len   = Math.Min(chunkSize, fileBytes.Length - off);
                    byte[] chunk = new byte[len];
                    Array.Copy(fileBytes, off, chunk, 0, len);
                    client.WmiRegSetString(stagingKey, "c" + chunkCount, Convert.ToBase64String(chunk));
                }

                // Step 2: Invoke Win32_Process.Create to reassemble file from registry.
                // PS command reads chunk values → writes file → sets done flag.
                // Passed as -EncodedCommand (UTF-16LE) so path is not plain-text in args.
                string psScript =
                    "try{" +
                    "$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('" + stagingKey + "');" +
                    "$o=[IO.File]::OpenWrite('" + remote + "');" +
                    "$o.SetLength(0);" +
                    "for($i=0;;$i++){$v=$k.GetValue(\"c$i\");if($v-eq$null){break};" +
                    "$b=[Convert]::FromBase64String($v);$o.Write($b,0,$b.Length)};" +
                    "$o.Flush();$o.Close();" +
                    "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('" + stagingKey + "',1).SetValue('done','ok')" +
                    "}catch{" +
                    "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('" + stagingKey + "',1).SetValue('done',\"ERR:$($_.Exception.Message)\")" +
                    "}";

                string encodedCmd = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));
                Helpers.PrintInfo("Invoking Win32_Process.Create via WMI...");
                int pid = client.WmiCreateProcess(
                    "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encodedCmd);
                Helpers.PrintInfo("Process spawned (PID " + pid + ") — waiting for exit...");

                // Step 3: Poll for process exit via WS-Man Get (no child process)
                int maxWait = 300;
                for (int i = 0; i < maxWait; i++)
                {
                    System.Threading.Thread.Sleep(1000);
                    if (!client.WmiProcessExists(pid)) break;
                }

                // Step 4: Read done sentinel once after process exits
                System.Threading.Thread.Sleep(500);
                string done = client.WmiRegGetString(stagingKey, "done");

                // Step 5: Clean up staging key regardless of outcome
                try { client.WmiRegDeleteKey(stagingKey); } catch { }

                if (done != null && done.StartsWith("ERR:"))
                    throw new Exception("Remote write failed: " + done.Substring(4));

                Helpers.PrintSuccess("Uploaded " + fileBytes.Length + " bytes → " + remote);
            }
        }
    }
}
