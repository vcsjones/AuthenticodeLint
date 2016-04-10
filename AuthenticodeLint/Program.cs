using System;
using System.Linq;

namespace AuthenticodeLint
{
    class Program
    {
        static void Main(string[] args)
        {
            var commandLineRaw = string.Join(" ", args);
            var commandLine = CommandLineParser.LexCommandLine(commandLineRaw);
            var parsedCommandLine = CommandLineParser.CreateCommandLineParametersWithValues(commandLine).ToList();
            if (parsedCommandLine.Count == 0 || parsedCommandLine.Any(cl => cl.Name == "help"))
            {
                ShowHelp();
            }
        }

        static void ShowHelp()
        {
            Console.Out.WriteLine(@"Authenticode Linter

Checks the authenticode signature of your binaries.

Usage: authlint.exe -in ""C:\path to an\executable.exe""

    -in:        A path to an executable, DLL, or MSI to lint. Required.
    -suppress:  A comma separated list of error or warning IDs to ignore. Optional.
    -q|quite:   Run quitely and do not print anything to the output. Optional.
    -report:    A path to produce an XML file as a report. Optional.

Exit codes:

    0:      All checks passed, excluding any that were suppressed.
    1:      One or more checks failed.
    2:      The target specified is not authenticode signed at all.
");
        }
    }
}
