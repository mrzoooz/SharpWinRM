using System;

namespace SharpWinRM
{
    internal static class Helpers
    {
        internal static bool NoColors = false;

        internal static void PrintInfo(string msg)    => Write("[*] " + msg, null);
        internal static void PrintSuccess(string msg) => Write("[+] " + msg, ConsoleColor.Green);
        internal static void PrintError(string msg)   => Write("[-] " + msg, ConsoleColor.Red);
        internal static void PrintWarn(string msg)    => Write("[!] " + msg, ConsoleColor.Yellow);

        private static void Write(string msg, ConsoleColor? col)
        {
            if (!NoColors && col.HasValue)
            {
                Console.ForegroundColor = col.Value;
                Console.WriteLine(msg);
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine(msg);
            }
        }
    }
}
