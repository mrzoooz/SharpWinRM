using System;
using System.Net.Sockets;

namespace SharpWinRM.Commands
{
    internal class Scan
    {
        internal static void Run(ArgumentParser args)
        {
            string target = args.Get("target");
            if (string.IsNullOrEmpty(target))
            {
                Helpers.PrintError("Missing /target:");
                return;
            }

            Console.WriteLine();
            Helpers.PrintInfo("Target : " + target);
            Console.WriteLine();

            bool http  = Probe(target, 5985);
            bool https = Probe(target, 5986);

            if (http)  Helpers.PrintSuccess("5985 OPEN  — WinRM HTTP  (use without /ssl)");
            else       Helpers.PrintWarn   ("5985 closed / filtered");

            if (https) Helpers.PrintSuccess("5986 OPEN  — WinRM HTTPS (use /ssl for encrypted transport)");
            else       Helpers.PrintWarn   ("5986 closed / filtered");

            Console.WriteLine();

            if (https)       Helpers.PrintInfo("Recommendation: use /ssl (port 5986) — TLS hides SOAP traffic from the wire");
            else if (http)   Helpers.PrintInfo("Recommendation: port 5985 only — Kerberos/NTLM provide message-level encryption");
            else             Helpers.PrintError("No WinRM port reachable on " + target);
        }

        private static bool Probe(string host, int port)
        {
            try
            {
                using (var tcp = new TcpClient())
                {
                    var ar = tcp.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(3))) return false;
                    tcp.EndConnect(ar);
                    return tcp.Connected;
                }
            }
            catch { return false; }
        }
    }
}
