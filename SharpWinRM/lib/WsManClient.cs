using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Xml;

namespace SharpWinRM
{
    /// <summary>
    /// COM-based WS-Man client via WSMan.Automation (wsmauto.dll).
    /// All remote operations use WMI method invocation over WS-Man.
    /// Remote process tree: svchost (WinMgmt) → wmiprvse.exe (→ child only for CreateProcess).
    /// </summary>
    internal class WsManClient : IDisposable
    {
        private readonly dynamic _wsman;
        private readonly dynamic _session;
        private readonly WindowsImpersonationContext _impCtx;
        private readonly IntPtr _token;

        // WMI class base URI — all WMI method calls use this prefix.
        private const string WmiBase = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/";
        // HKEY_LOCAL_MACHINE = 0x80000002 expressed as uint32 for StdRegProv
        private const string Hklm = "2147483650";

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

            Type wsmanType = Type.GetTypeFromProgID("WSMan.Automation", true);
            dynamic wsman  = Activator.CreateInstance(wsmanType);

            const int WSManFlagUTF8                = 0x00000001;
            const int WSManFlagCredUserNamePassword = 0x00001000;
            const int WSManFlagSkipCACheck          = 0x00002000;
            const int WSManFlagSkipCNCheck          = 0x00004000;
            const int WSManFlagUseNegotiate         = 0x00020000;
            const int WSManFlagUseKerberos          = 0x00080000;

            int flags;
            dynamic opts = null;

            if (ctx.Auth == AuthMode.Ptt || ctx.Auth == AuthMode.Ticket)
            {
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

        // ── WMI Win32_Process ──────────────────────────────────────────────────────

        // Invokes Win32_Process.Create. Returns the PID of the spawned process.
        // Remote process tree: svchost (WinMgmt) → wmiprvse.exe → <process>
        internal int WmiCreateProcess(string commandLine)
        {
            string classUri  = WmiBase + "Win32_Process";
            string actionUri = classUri + "/Create";
            string body =
                "<p:Create_INPUT xmlns:p=\"" + classUri + "\">" +
                "<p:CommandLine>" + XmlEscape(commandLine) + "</p:CommandLine>" +
                "</p:Create_INPUT>";

            string resp = (string)_session.Invoke(actionUri, classUri, body, 0);
            var doc = new XmlDocument(); doc.LoadXml(resp);

            string retVal = SelectLocalName(doc, "ReturnValue") ?? "-1";
            if (retVal != "0")
                throw new Exception("Win32_Process.Create failed (ReturnValue=" + retVal + ")");

            return int.Parse(SelectLocalName(doc, "ProcessId") ?? "0");
        }

        // Returns true if a process with the given PID still exists on the remote.
        // Uses WS-Man Get with the Win32_Process Handle key — throws a SOAP fault if gone.
        internal bool WmiProcessExists(int pid)
        {
            try
            {
                _session.Get(WmiBase + "Win32_Process?Handle=" + pid, 0);
                return true;
            }
            catch { return false; }
        }

        // ── WMI StdRegProv — no child process for any of these ────────────────────

        // Creates a registry key under HKLM.
        internal void WmiRegCreateKey(string subKey)
        {
            string classUri  = WmiBase + "StdRegProv";
            string actionUri = classUri + "/CreateKey";
            string body =
                "<p:CreateKey_INPUT xmlns:p=\"" + classUri + "\">" +
                "<p:hDefKey>" + Hklm + "</p:hDefKey>" +
                "<p:sSubKeyName>" + XmlEscape(subKey) + "</p:sSubKeyName>" +
                "</p:CreateKey_INPUT>";

            _session.Invoke(actionUri, classUri, body, 0);
        }

        // Writes a REG_SZ value to HKLM. Key must already exist.
        internal void WmiRegSetString(string subKey, string valueName, string value)
        {
            string classUri  = WmiBase + "StdRegProv";
            string actionUri = classUri + "/SetStringValue";
            string body =
                "<p:SetStringValue_INPUT xmlns:p=\"" + classUri + "\">" +
                "<p:hDefKey>" + Hklm + "</p:hDefKey>" +
                "<p:sSubKeyName>" + XmlEscape(subKey) + "</p:sSubKeyName>" +
                "<p:sValueName>" + XmlEscape(valueName) + "</p:sValueName>" +
                "<p:sValue>" + XmlEscape(value) + "</p:sValue>" +
                "</p:SetStringValue_INPUT>";

            _session.Invoke(actionUri, classUri, body, 0);
        }

        // Reads a REG_SZ value from HKLM. Returns null if the value does not exist.
        internal string WmiRegGetString(string subKey, string valueName)
        {
            string classUri  = WmiBase + "StdRegProv";
            string actionUri = classUri + "/GetStringValue";
            string body =
                "<p:GetStringValue_INPUT xmlns:p=\"" + classUri + "\">" +
                "<p:hDefKey>" + Hklm + "</p:hDefKey>" +
                "<p:sSubKeyName>" + XmlEscape(subKey) + "</p:sSubKeyName>" +
                "<p:sValueName>" + XmlEscape(valueName) + "</p:sValueName>" +
                "</p:GetStringValue_INPUT>";

            string resp = (string)_session.Invoke(actionUri, classUri, body, 0);
            var doc = new XmlDocument(); doc.LoadXml(resp);

            if ((SelectLocalName(doc, "ReturnValue") ?? "-1") != "0") return null;
            return SelectLocalName(doc, "sValue");
        }

        // Deletes a single registry value from HKLM.
        internal void WmiRegDeleteValue(string subKey, string valueName)
        {
            string classUri  = WmiBase + "StdRegProv";
            string actionUri = classUri + "/DeleteValue";
            string body =
                "<p:DeleteValue_INPUT xmlns:p=\"" + classUri + "\">" +
                "<p:hDefKey>" + Hklm + "</p:hDefKey>" +
                "<p:sSubKeyName>" + XmlEscape(subKey) + "</p:sSubKeyName>" +
                "<p:sValueName>" + XmlEscape(valueName) + "</p:sValueName>" +
                "</p:DeleteValue_INPUT>";

            _session.Invoke(actionUri, classUri, body, 0);
        }

        // Deletes an entire registry key (and all its values) from HKLM.
        internal void WmiRegDeleteKey(string subKey)
        {
            string classUri  = WmiBase + "StdRegProv";
            string actionUri = classUri + "/DeleteKey";
            string body =
                "<p:DeleteKey_INPUT xmlns:p=\"" + classUri + "\">" +
                "<p:hDefKey>" + Hklm + "</p:hDefKey>" +
                "<p:sSubKeyName>" + XmlEscape(subKey) + "</p:sSubKeyName>" +
                "</p:DeleteKey_INPUT>";

            _session.Invoke(actionUri, classUri, body, 0);
        }

        // ── Helpers ────────────────────────────────────────────────────────────────

        // Matches XML elements by local-name, ignoring namespace prefixes.
        // WMI responses vary by Windows version; this handles all of them.
        private static string SelectLocalName(XmlDocument doc, string localName) =>
            doc.SelectSingleNode("//*[local-name()='" + localName + "']")?.InnerText;

        private static string XmlEscape(string s) =>
            s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
             .Replace("\"", "&quot;").Replace("'", "&apos;");

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
