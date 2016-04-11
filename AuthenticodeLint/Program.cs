using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthenticodeLint
{
    class Program
    {
        static int Main(string[] args)
        {
            var commandLineRaw = string.Join(" ", args);
            var commandLine = CommandLineParser.LexCommandLine(commandLineRaw);
            var parsedCommandLine = CommandLineParser.CreateCommandLineParametersWithValues(commandLine).ToList();
            if (parsedCommandLine.Count == 0 || parsedCommandLine.Any(cl => cl.Name == "help"))
            {
                ShowHelp();
                //Avoid returning success for printing help so that automated build systems do not interpret "show the help"
                //As a successful build incase the build system is incorrectly passing arguments.
                return ExitCodes.InvalidInputOrConfig;
            }
            string input = null;
            var suppress = new HashSet<int>();
            bool quiet = false;
            string report = null;
            foreach(var parameter in parsedCommandLine)
            {
                if (parameter.Name == "in")
                {
                    input = parameter.Value;
                }
                else if (parameter.Name == "suppress")
                {
                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        ShowInvalidSuppression();
                        return ExitCodes.InvalidInputOrConfig;
                    }
                    foreach(var idString in parameter.Value.Split(',').Select(p => p.Trim()))
                    {
                        int id;
                        if (int.TryParse(idString, out id))
                        {
                            suppress.Add(id);
                        }
                        else
                        {
                            Console.Error.WriteLine($"{idString} is not a valid error ID.");
                            return ExitCodes.InvalidInputOrConfig;
                        }
                    }
                }
                else if (parameter.Name == "q" || parameter.Name == "quiet")
                {
                    if (!string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Value} does not expect a value.");
                        return ExitCodes.InvalidInputOrConfig;
                    }
                    quiet = true;
                }
                else if (parameter.Name == "report")
                {
                    report = parameter.Value;
                }
                else
                {
                    Console.Error.WriteLine($"-{parameter.Name} is an unknown parameter.");
                    return ExitCodes.InvalidInputOrConfig;
                }
            }
            if (string.IsNullOrWhiteSpace(input))
            {
                Console.Error.WriteLine("Input is expected. See -help for usage.");
                return ExitCodes.InvalidInputOrConfig;
            }
            var configuration = new CheckConfiguration(input, report, quiet, suppress);

            if (!ConfigurationValidator.ValidateAndPrint(configuration, Console.Error))
            {
                return ExitCodes.InvalidInputOrConfig;
            }
            var extractor = new SignatureExtractor();
            var signatures = extractor.Extract(input);
            if (signatures.Count == 0)
            {
                if (!quiet)
                {
                    Console.Out.WriteLine("File is not authenticode signed.");
                }
                return ExitCodes.NoAuthenticodeSignature;
            }
            var collectors = new List<IRuleResultCollector>();
            if (!quiet)
            {
                collectors.Add(new StdOutResultCollector());
            }
            var result = CheckEngine.Instance.RunAllRules(signatures, collectors, suppress);
            return result == RuleEngineResult.AllPass ? ExitCodes.Success : ExitCodes.ChecksFailed;
        }

        static void ShowInvalidSuppression() => Console.Error.WriteLine("Invalid list of errors to suppress. Use -help for more information.");

        static void ShowHelp()
        {
            Console.Out.WriteLine(@"Authenticode Linter

Checks the authenticode signature of your binaries.

Usage: authlint.exe -in ""C:\path to an\executable.exe""

    -in:        A path to an executable, DLL, or MSI to lint. Required.
    -suppress:  A comma separated list of error IDs to ignore. All checks are run if omitted. Optional.
    -q|quite:   Run quitely and do not print anything to the output. Optional.
    -report:    A path to produce an XML file as a report. Optional.

Exit codes:

    0:      All checks passed, excluding any that were suppressed.
    1:      Invalid input or configuration was specified.
    2:      One or more checks failed.
    3:      The target specified is not authenticode signed at all.
");
        }
    }

    internal static class ExitCodes
    {
        public static int Success { get; } = 0;
        public static int InvalidInputOrConfig { get; } = 1;
        public static int ChecksFailed { get; } = 2;
        public static int NoAuthenticodeSignature { get; } = 3;
        public static int UnknownResults { get; } = 0xFF;
    }
}
