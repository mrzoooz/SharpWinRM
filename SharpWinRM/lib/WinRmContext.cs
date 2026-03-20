namespace SharpWinRM
{
    internal class WinRmContext
    {
        internal string   Target    { get; set; }
        internal int      Port      { get; set; } = 5985;
        internal bool     Ssl       { get; set; }
        internal string   Username  { get; set; }
        internal string   Domain    { get; set; }
        internal string   Password  { get; set; }
        internal string   Ticket    { get; set; }  // base64 kirbi or file path
        internal AuthMode Auth      { get; set; } = AuthMode.Password;
        internal int      TimeoutMs { get; set; } = 30000;

        internal string Url =>
            (Ssl ? "https" : "http") + "://" + Target + ":" + Port + "/wsman";

        internal string DisplayUser =>
            (Domain != null ? Domain + "\\" : "") + Username;
    }

    internal enum AuthMode
    {
        Password,
        Ptt,     // ticket already in session (klist)
        Ticket   // import supplied kirbi then connect
    }
}
