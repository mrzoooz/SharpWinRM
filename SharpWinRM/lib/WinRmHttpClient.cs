using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Xml;

namespace SharpWinRM
{
    /// <summary>
    /// WinRM client using raw HttpClient + Windows SSPI.
    /// Avoids loading wsmauto.dll (WSMan.Automation COM) entirely.
    ///   Password → explicit NetworkCredential over NTLM
    ///   Ptt      → DefaultNetworkCredentials over Negotiate (picks up current session's Kerberos ticket)
    ///   Ticket   → same as Ptt, but called while impersonating a sacrificial logon session
    /// </summary>
    internal sealed class WinRmHttpClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly string     _endpoint;

        // WS-Management namespaces
        private const string SoapNs   = "http://www.w3.org/2003/05/soap-envelope";
        private const string WsaNs    = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
        private const string WsManNs  = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
        private const string ShellNs  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
        private const string ShellUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
        private const string AnonAddr = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

        // WS-Management actions
        private const string ActionCreate  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
        private const string ActionCmd     = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
        private const string ActionReceive = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
        private const string ActionSignal  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
        private const string ActionDelete  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

        internal static WinRmHttpClient Create(WinRmContext ctx)
        {
            var uri     = new Uri(ctx.Url);
            var handler = new HttpClientHandler
            {
                PreAuthenticate   = false,
                AllowAutoRedirect = false,
            };

            if (ctx.Auth == AuthMode.Password)
            {
                // Explicit credentials — NTLM. Reliable across domain/workgroup/local.
                var cache = new CredentialCache();
                cache.Add(uri, "Ntlm",
                    new NetworkCredential(ctx.Username, ctx.Password, ctx.Domain ?? "."));
                handler.Credentials = cache;
            }
            else
            {
                // Kerberos (Ptt or Ticket): use the current thread's SSPI context.
                // For Ptt  → picks up the ticket already in this session.
                // For Ticket → called while impersonating a sacrificial logon session
                //              that has the imported TGT, so SSPI uses that session's cache.
                var cache = new CredentialCache();
                cache.Add(uri, "Negotiate", CredentialCache.DefaultNetworkCredentials);
                handler.Credentials = cache;
            }

            if (ctx.Ssl)
                handler.ServerCertificateCustomValidationCallback = (_, __, ___, ____) => true;

            var http = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(ctx.TimeoutMs),
            };

            // Match the User-Agent sent by the Windows built-in WinRM client
            // so the connection blends with legitimate management traffic.
            http.DefaultRequestHeaders.TryAddWithoutValidation(
                "User-Agent", "Microsoft WinRM Client");

            return new WinRmHttpClient(http, ctx.Url);
        }

        private WinRmHttpClient(HttpClient http, string endpoint)
        {
            _http     = http;
            _endpoint = endpoint;
        }

        internal string RunCommand(string command)
        {
            string shellId = CreateShell();
            try
            {
                string commandId = InvokeCommand(shellId, command);
                string output    = ReceiveOutput(shellId, commandId);
                try { Signal(shellId, commandId); } catch { }
                return output;
            }
            finally
            {
                try { DeleteShell(shellId); } catch { }
            }
        }

        // ── WS-Management operations ────────────────────────────────────────

        private string CreateShell()
        {
            string body =
                "<rsp:Shell xmlns:rsp=\"" + ShellNs + "\">" +
                "<rsp:InputStreams>stdin</rsp:InputStreams>" +
                "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
                "</rsp:Shell>";

            string resp = Post(Envelope(ActionCreate, ShellUri, null, body));

            return XPathValue(resp, "//w:Selector[@Name='ShellId']")
                ?? XPathValue(resp, "//rsp:Shell/rsp:ShellId")
                ?? throw new Exception("Could not parse ShellId from response.");
        }

        private string InvokeCommand(string shellId, string command)
        {
            string body =
                "<rsp:CommandLine xmlns:rsp=\"" + ShellNs + "\">" +
                "<rsp:Command>cmd.exe</rsp:Command>" +
                "<rsp:Arguments>/c " + XmlEscape(command) + "</rsp:Arguments>" +
                "</rsp:CommandLine>";

            string resp = Post(Envelope(ActionCmd, ShellUri, shellId, body));

            return XPathValue(resp, "//rsp:CommandId")
                ?? throw new Exception("Could not parse CommandId from response.");
        }

        private string ReceiveOutput(string shellId, string commandId)
        {
            var output = new StringBuilder();
            bool done  = false;

            while (!done)
            {
                string body =
                    "<rsp:Receive xmlns:rsp=\"" + ShellNs + "\">" +
                    "<rsp:DesiredStream CommandId=\"" + commandId +
                    "\">stdout stderr</rsp:DesiredStream>" +
                    "</rsp:Receive>";

                string resp = Post(Envelope(ActionReceive, ShellUri, shellId, body));
                var doc = new XmlDocument();
                doc.LoadXml(resp);

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

        private void Signal(string shellId, string commandId)
        {
            string body =
                "<rsp:Signal xmlns:rsp=\"" + ShellNs + "\" CommandId=\"" + commandId + "\">" +
                "<rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c</rsp:Code>" +
                "</rsp:Signal>";
            Post(Envelope(ActionSignal, ShellUri, shellId, body));
        }

        private void DeleteShell(string shellId)
        {
            Post(Envelope(ActionDelete, ShellUri, shellId, ""));
        }

        // ── SOAP builder ────────────────────────────────────────────────────

        private string Envelope(string action, string resourceUri,
            string shellId, string bodyContent)
        {
            var sb = new StringBuilder();
            sb.Append("<s:Envelope")
              .Append(" xmlns:s=\"").Append(SoapNs).Append('"')
              .Append(" xmlns:wsa=\"").Append(WsaNs).Append('"')
              .Append(" xmlns:w=\"").Append(WsManNs).Append('"')
              .Append(" xmlns:rsp=\"").Append(ShellNs).Append('"')
              .Append("><s:Header>");

            sb.Append("<wsa:To>").Append(XmlEscape(_endpoint)).Append("</wsa:To>");
            sb.Append("<wsa:ReplyTo><wsa:Address s:mustUnderstand=\"true\">")
              .Append(AnonAddr).Append("</wsa:Address></wsa:ReplyTo>");
            sb.Append("<wsa:MessageID>uuid:").Append(Guid.NewGuid()).Append("</wsa:MessageID>");
            sb.Append("<wsa:Action s:mustUnderstand=\"true\">").Append(action).Append("</wsa:Action>");
            sb.Append("<w:ResourceURI s:mustUnderstand=\"true\">").Append(resourceUri).Append("</w:ResourceURI>");
            sb.Append("<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>");
            sb.Append("<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>");
            sb.Append("<w:OperationTimeout>PT")
              .Append((_http.Timeout.TotalSeconds).ToString("F3"))
              .Append("S</w:OperationTimeout>");

            if (!string.IsNullOrEmpty(shellId))
                sb.Append("<w:SelectorSet><w:Selector Name=\"ShellId\">")
                  .Append(shellId)
                  .Append("</w:Selector></w:SelectorSet>");

            sb.Append("</s:Header><s:Body>").Append(bodyContent).Append("</s:Body></s:Envelope>");
            return sb.ToString();
        }

        // ── HTTP transport ──────────────────────────────────────────────────

        private string Post(string soap)
        {
            using (var content = new StringContent(soap, Encoding.UTF8, "application/soap+xml"))
            {
                var resp = _http.PostAsync(_endpoint, content).GetAwaiter().GetResult();
                string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                if (!resp.IsSuccessStatusCode && (int)resp.StatusCode != 200)
                {
                    // Extract SOAP fault text if present, otherwise surface HTTP status
                    string fault = XPathValue(body,
                        "//s:Body/s:Fault/s:Detail/f:WSManFault/f:Message") ??
                        XPathValue(body, "//s:Body/s:Fault/s:Reason/s:Text");
                    if (!string.IsNullOrEmpty(fault))
                        throw new Exception("WinRM fault: " + fault.Trim());
                    throw new Exception("HTTP " + (int)resp.StatusCode + " " + resp.ReasonPhrase);
                }

                return body;
            }
        }

        // ── XML helpers ─────────────────────────────────────────────────────

        private static string XPathValue(string xml, string xpath)
        {
            if (string.IsNullOrEmpty(xml)) return null;
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(xml);
                var ns = new XmlNamespaceManager(doc.NameTable);
                ns.AddNamespace("s",   SoapNs);
                ns.AddNamespace("wsa", WsaNs);
                ns.AddNamespace("w",   WsManNs);
                ns.AddNamespace("rsp", ShellNs);
                ns.AddNamespace("f",
                    "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault");
                return doc.SelectSingleNode(xpath, ns)?.InnerText;
            }
            catch { return null; }
        }

        private static string XmlEscape(string s) =>
            s.Replace("&",  "&amp;")
             .Replace("<",  "&lt;")
             .Replace(">",  "&gt;")
             .Replace("\"", "&quot;")
             .Replace("'",  "&apos;");

        public void Dispose() => _http?.Dispose();
    }
}
