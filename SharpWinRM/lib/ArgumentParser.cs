using System;
using System.Collections.Generic;

namespace SharpWinRM
{
    internal class ArgumentParser
    {
        private readonly Dictionary<string, string> _args =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private string _command;

        internal ArgumentParser(string[] args)
        {
            if (args.Length > 0 && !args[0].StartsWith("/"))
                _command = args[0].ToLower();

            string lastKey = null;
            foreach (string a in args)
            {
                if (!a.StartsWith("/"))
                {
                    // Token with no leading '/' and not the command — space-separated
                    // continuation of the previous flag's value (e.g. /command:dir C:\Temp)
                    if (lastKey != null)
                        _args[lastKey] = _args[lastKey] + " " + a;
                    continue;
                }
                int colon = a.IndexOf(':');
                if (colon > 0)
                {
                    lastKey = a.Substring(1, colon - 1);
                    _args[lastKey] = a.Substring(colon + 1);
                }
                else
                {
                    lastKey = a.Substring(1);
                    _args[lastKey] = "true";
                }
            }
        }

        internal string Command               => _command;
        internal bool   Has(string key)       => _args.ContainsKey(key);
        internal string Get(string key, string def = null)
            => _args.TryGetValue(key, out string v) ? v : def;
    }
}
