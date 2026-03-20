using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Xml;

namespace SharpWinRM
{
    /// <summary>
    /// COM-based WinRM client via WSMan.Automation (wsmauto.dll).
    /// Used for /password: and /kerberos: — Windows handles auth.
    /// For /rc4: (pass-the-hash), WinRmHttpClient is used instead.
    /// </summary>
    internal class WsManClient : IDisposable
    {
        private readonly dynamic _wsman;
        private readonly dynamic _session;
        private readonly WindowsImpersonationContext _impCtx;
        private readonly IntPtr _token;

        private const string ShellUri   = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
        private const string ShellNs    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
        private const string ActionCmd  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
        private const string ActionRecv = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
        private const string ActionSig  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
        private const string ActionSend = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send";

        internal static WsManClient Create(WinRmContext ctx)
        {
            IntPtr token = IntPtr.Zero;
            WindowsImpersonationContext impCtx = null;

            if (ctx.Auth == AuthMode.Password &&
                !string.IsNullOrEmpty(ctx.Username) &&
                !string.IsNullOrEmpty(ctx.Password))
            {
                // LogonUser type-9: network-only credential swap, no local auth
                bool ok = LogonUser(ctx.Username, ctx.Domain ?? ".", ctx.Password,
                    9, 3, out token);
                if (!ok)
                    Helpers.PrintWarn("LogonUser failed (" + Marshal.GetLastWin32Error() + ") — using current token");
                else
                    impCtx = new WindowsIdentity(token).Impersonate();
            }
            // Kerberos: no impersonation — use current token as-is

            Type wsmanType = Type.GetTypeFromProgID("WSMan.Automation", true);
            dynamic wsman  = Activator.CreateInstance(wsmanType);

            // WSMan session flags (from Windows SDK wsmanautomation.h)
            const int WSManFlagUTF8                 = 0x00000001;
            const int WSManFlagCredUserNamePassword  = 0x00001000;
            const int WSManFlagSkipCACheck           = 0x00002000;
            const int WSManFlagSkipCNCheck           = 0x00004000;
            const int WSManFlagUseNegotiate          = 0x00020000;
            const int WSManFlagUseKerberos           = 0x00080000;

            int flags;
            dynamic opts = null;

            if (ctx.Auth == AuthMode.Ptt || ctx.Auth == AuthMode.Ticket)
            {
                // Kerberos provides GSSAPI message-level encryption over HTTP —
                // no NoEncryption/UseSsl flag needed; AllowUnencrypted doesn't apply.
                flags = WSManFlagUseKerberos
                      | WSManFlagUTF8
                      | WSManFlagSkipCACheck
                      | WSManFlagSkipCNCheck;
            }
            else
            {
                opts          = wsman.CreateConnectionOptions();
                opts.UserName = ctx.DisplayUser;
                opts.Password = ctx.Password;
                flags = WSManFlagCredUserNamePassword
                      | WSManFlagUseNegotiate
                      | WSManFlagUTF8
                      | WSManFlagSkipCACheck
                      | WSManFlagSkipCNCheck;
            }

            dynamic session = wsman.CreateSession(ctx.Url, flags,
                (ctx.Auth == AuthMode.Ptt || ctx.Auth == AuthMode.Ticket) ? Type.Missing : opts);
            session.Timeout = ctx.TimeoutMs;

            return new WsManClient(wsman, session, impCtx, token);
        }

        private WsManClient(dynamic wsman, dynamic session,
            WindowsImpersonationContext impCtx, IntPtr token)
        {
            _wsman = wsman; _session = session; _impCtx = impCtx; _token = token;
        }

        internal string RunCommand(string command)
        {
            string createBody =
                "<rsp:Shell xmlns:rsp=\"" + ShellNs + "\">" +
                "<rsp:InputStreams>stdin</rsp:InputStreams>" +
                "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
                "</rsp:Shell>";

            string shellResp = (string)_session.Create(ShellUri, createBody, 0);
            string shellId   = ParseShellId(shellResp);
            if (string.IsNullOrEmpty(shellId))
                throw new Exception("Could not parse ShellId.");

            string shellWithId = ShellUri + "?ShellId=" + shellId;
            try
            {
                string cmdBody =
                    "<rsp:CommandLine xmlns:rsp=\"" + ShellNs + "\">" +
                    "<rsp:Command>cmd.exe</rsp:Command>" +
                    "<rsp:Arguments>/c " + XmlEscape(command) + "</rsp:Arguments>" +
                    "</rsp:CommandLine>";

                string cmdResp   = (string)_session.Invoke(ActionCmd, shellWithId, cmdBody, 0);
                string commandId = ParseCommandId(cmdResp);
                if (string.IsNullOrEmpty(commandId))
                    throw new Exception("Could not parse CommandId.");

                var output = new StringBuilder();
                bool done  = false;
                while (!done)
                {
                    string recvBody =
                        "<rsp:Receive xmlns:rsp=\"" + ShellNs + "\">" +
                        "<rsp:DesiredStream CommandId=\"" + commandId +
                        "\">stdout stderr</rsp:DesiredStream>" +
                        "</rsp:Receive>";

                    string recvResp = (string)_session.Invoke(ActionRecv, shellWithId, recvBody, 0);
                    var doc = new XmlDocument(); doc.LoadXml(recvResp);
                    foreach (XmlNode node in doc.GetElementsByTagName("Stream", ShellNs))
                        if (!string.IsNullOrEmpty(node.InnerText))
                            output.Append(Encoding.UTF8.GetString(
                                Convert.FromBase64String(node.InnerText)));
                    var states = doc.GetElementsByTagName("CommandState", ShellNs);
                    if (states.Count > 0 &&
                        ((XmlElement)states[0]).GetAttribute("State").EndsWith("Done"))
                        done = true;
                }

                try
                {
                    string sigBody =
                        "<rsp:Signal xmlns:rsp=\"" + ShellNs + "\" CommandId=\"" + commandId + "\">" +
                        "<rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c</rsp:Code>" +
                        "</rsp:Signal>";
                    _session.Invoke(ActionSig, shellWithId, sigBody, 0);
                }
                catch { }

                return output.ToString();
            }
            finally
            {
                try { _session.Delete(shellWithId, 0); } catch { }
            }
        }

        // Runs command via cmd.exe and returns raw stdout bytes.
        // Unlike RunCommand, this separates stdout from stderr and never decodes as
        // UTF-8 — preserving binary content byte-for-byte as it comes off the pipe.
        internal byte[] RunCommandBytes(string command)
        {
            string createBody =
                "<rsp:Shell xmlns:rsp=\"" + ShellNs + "\">" +
                "<rsp:InputStreams>stdin</rsp:InputStreams>" +
                "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
                "</rsp:Shell>";

            string shellResp = (string)_session.Create(ShellUri, createBody, 0);
            string shellId   = ParseShellId(shellResp);
            if (string.IsNullOrEmpty(shellId))
                throw new Exception("Could not parse ShellId.");

            string shellWithId = ShellUri + "?ShellId=" + shellId;
            try
            {
                string cmdBody =
                    "<rsp:CommandLine xmlns:rsp=\"" + ShellNs + "\">" +
                    "<rsp:Command>cmd.exe</rsp:Command>" +
                    "<rsp:Arguments>/c " + XmlEscape(command) + "</rsp:Arguments>" +
                    "</rsp:CommandLine>";

                string cmdResp   = (string)_session.Invoke(ActionCmd, shellWithId, cmdBody, 0);
                string commandId = ParseCommandId(cmdResp);
                if (string.IsNullOrEmpty(commandId))
                    throw new Exception("Could not parse CommandId.");

                var  stdoutBytes = new List<byte>();
                var  stderrText  = new StringBuilder();
                bool done        = false;
                while (!done)
                {
                    string recvBody =
                        "<rsp:Receive xmlns:rsp=\"" + ShellNs + "\">" +
                        "<rsp:DesiredStream CommandId=\"" + commandId +
                        "\">stdout stderr</rsp:DesiredStream>" +
                        "</rsp:Receive>";
                    string recvResp = (string)_session.Invoke(ActionRecv, shellWithId, recvBody, 0);
                    var doc = new XmlDocument(); doc.LoadXml(recvResp);
                    foreach (XmlNode node in doc.GetElementsByTagName("Stream", ShellNs))
                    {
                        if (string.IsNullOrEmpty(node.InnerText)) continue;
                        byte[] chunk = Convert.FromBase64String(node.InnerText);
                        if (((XmlElement)node).GetAttribute("Name") == "stdout")
                            stdoutBytes.AddRange(chunk);
                        else
                            stderrText.Append(Encoding.UTF8.GetString(chunk));
                    }
                    var states = doc.GetElementsByTagName("CommandState", ShellNs);
                    if (states.Count > 0 &&
                        ((XmlElement)states[0]).GetAttribute("State").EndsWith("Done"))
                        done = true;
                }

                if (stdoutBytes.Count == 0 && stderrText.Length > 0)
                    throw new Exception(stderrText.ToString().Trim());

                return stdoutBytes.ToArray();
            }
            finally
            {
                try { _session.Delete(shellWithId, 0); } catch { }
            }
        }

        // Starts exe directly (no cmd.exe wrapper) and pipes stdinBytes via the WinRM
        // Send action.  File data travels through the stdin channel — never a command line.
        internal string RunWithStdin(string exe, string exeArgs, byte[] stdinBytes)
        {
            string createBody =
                "<rsp:Shell xmlns:rsp=\"" + ShellNs + "\">" +
                "<rsp:InputStreams>stdin</rsp:InputStreams>" +
                "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
                "</rsp:Shell>";

            string shellResp = (string)_session.Create(ShellUri, createBody, 0);
            string shellId   = ParseShellId(shellResp);
            if (string.IsNullOrEmpty(shellId))
                throw new Exception("Could not parse ShellId.");

            string shellWithId = ShellUri + "?ShellId=" + shellId;
            try
            {
                string cmdBody =
                    "<rsp:CommandLine xmlns:rsp=\"" + ShellNs + "\">" +
                    "<rsp:Command>" + XmlEscape(exe) + "</rsp:Command>" +
                    "<rsp:Arguments>" + XmlEscape(exeArgs) + "</rsp:Arguments>" +
                    "</rsp:CommandLine>";

                string cmdResp   = (string)_session.Invoke(ActionCmd, shellWithId, cmdBody, 0);
                string commandId = ParseCommandId(cmdResp);
                if (string.IsNullOrEmpty(commandId))
                    throw new Exception("Could not parse CommandId.");

                // Push stdin in 64 KB chunks — each chunk is one WinRM Send message.
                const int chunkSize = 65536;
                for (int offset = 0; offset < stdinBytes.Length; offset += chunkSize)
                {
                    int    len   = Math.Min(chunkSize, stdinBytes.Length - offset);
                    byte[] chunk = new byte[len];
                    Array.Copy(stdinBytes, offset, chunk, 0, len);
                    string sendBody =
                        "<rsp:Send xmlns:rsp=\"" + ShellNs + "\">" +
                        "<rsp:Stream Name=\"stdin\" CommandId=\"" + commandId + "\">" +
                        Convert.ToBase64String(chunk) + "</rsp:Stream></rsp:Send>";
                    _session.Invoke(ActionSend, shellWithId, sendBody, 0);
                }

                // Close stdin (EOF) so the process knows input is done.
                string eofBody =
                    "<rsp:Send xmlns:rsp=\"" + ShellNs + "\">" +
                    "<rsp:Stream Name=\"stdin\" CommandId=\"" + commandId + "\" End=\"TRUE\"></rsp:Stream>" +
                    "</rsp:Send>";
                _session.Invoke(ActionSend, shellWithId, eofBody, 0);

                // Collect stdout/stderr until the process exits.
                var  output = new StringBuilder();
                bool done   = false;
                while (!done)
                {
                    string recvBody =
                        "<rsp:Receive xmlns:rsp=\"" + ShellNs + "\">" +
                        "<rsp:DesiredStream CommandId=\"" + commandId +
                        "\">stdout stderr</rsp:DesiredStream>" +
                        "</rsp:Receive>";
                    string recvResp = (string)_session.Invoke(ActionRecv, shellWithId, recvBody, 0);
                    var doc = new XmlDocument(); doc.LoadXml(recvResp);
                    foreach (XmlNode node in doc.GetElementsByTagName("Stream", ShellNs))
                        if (!string.IsNullOrEmpty(node.InnerText))
                            output.Append(Encoding.UTF8.GetString(
                                Convert.FromBase64String(node.InnerText)));
                    var states = doc.GetElementsByTagName("CommandState", ShellNs);
                    if (states.Count > 0 &&
                        ((XmlElement)states[0]).GetAttribute("State").EndsWith("Done"))
                        done = true;
                }
                return output.ToString();
            }
            finally
            {
                try { _session.Delete(shellWithId, 0); } catch { }
            }
        }

        private static string ParseShellId(string xml)
        {
            var doc = new XmlDocument(); doc.LoadXml(xml);
            var ns  = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("rsp", ShellNs);
            ns.AddNamespace("w", "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd");
            return doc.SelectSingleNode("//w:Selector[@Name='ShellId']", ns)?.InnerText
                ?? doc.SelectSingleNode("//rsp:Shell/rsp:ShellId", ns)?.InnerText
                ?? doc.DocumentElement?.InnerText?.Trim();
        }

        private static string ParseCommandId(string xml)
        {
            var doc = new XmlDocument(); doc.LoadXml(xml);
            var ns  = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("rsp", ShellNs);
            return doc.SelectSingleNode("//rsp:CommandId", ns)?.InnerText;
        }

        private static string XmlEscape(string s) =>
            s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;")
             .Replace("\"","&quot;").Replace("'","&apos;");

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string user, string domain, string password,
            int logonType, int logonProvider, out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public void Dispose()
        {
            try { Marshal.ReleaseComObject(_session); } catch { }
            try { Marshal.ReleaseComObject(_wsman);   } catch { }
            _impCtx?.Undo();
            if (_token != IntPtr.Zero) CloseHandle(_token);
        }
    }
}
