using System;
using System.Collections.Generic;
using System.IO;
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
            var inputs = new List<string>();
            var suppress = new HashSet<int>();
            bool quiet = false;
            bool verbose = false;
            string report = null;
            var revocation = RevocationChecking.None;
            foreach(var parameter in parsedCommandLine)
            {
                if (parameter.Name == "in")
                {
                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine("A value is required for input.");
                        return ExitCodes.InvalidInputOrConfig;
                    }
                    var filePattern = Path.GetFileName(parameter.Value);
                    //The value contains a pattern.
                    if (filePattern.Contains("*") || filePattern.Contains("?"))
                    {
                        var directory = Path.GetDirectoryName(parameter.Value);
                        if (Directory.Exists(directory))
                        {
                            var files = Directory.GetFiles(directory, filePattern, SearchOption.TopDirectoryOnly);
                            inputs.AddRange(files);
                        }
                    }
                    else
                    {
                        inputs.Add(parameter.Value);
                    }
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
                        Console.Error.WriteLine($"-{parameter.Name} does not expect a value.");
                        return ExitCodes.InvalidInputOrConfig;
                    }
                    quiet = true;
                }
                else if (parameter.Name == "verbose")
                {
                    if (!string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Name} does not expect a value.");
                        return ExitCodes.InvalidInputOrConfig;
                    }
                    verbose = true;
                }
                else if (parameter.Name == "report")
                {
                    report = parameter.Value;
                }
                else if (parameter.Name == "revocation")
                {
                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Name} requires a value if specified.");
                        return ExitCodes.InvalidInputOrConfig;
                    }
                    if (!Enum.TryParse(parameter.Value, true, out revocation))
                    {
                        Console.Error.WriteLine($"-{parameter.Value} is an unrecognized revocation mode.");
                        return ExitCodes.InvalidInputOrConfig;
                    }
                }
                else
                {
                    Console.Error.WriteLine($"-{parameter.Name} is an unknown parameter.");
                    return ExitCodes.InvalidInputOrConfig;
                }
            }
            if (inputs.Count == 0)
            {
                Console.Error.WriteLine("Input is expected. See -help for usage.");
                return ExitCodes.InvalidInputOrConfig;
            }
            var configuration = new CheckConfiguration(inputs, report, quiet, suppress, verbose, revocation);

            if (!ConfigurationValidator.ValidateAndPrint(configuration, Console.Error))
            {
                return ExitCodes.InvalidInputOrConfig;
            }
            var extractor = new SignatureExtractor();
            var collectors = new List<IRuleResultCollector>();
            if (!quiet)
            {
                collectors.Add(new StdOutRuleResultCollector());
            }
            if (!string.IsNullOrWhiteSpace(report))
            {
                collectors.Add(new XmlRuleResultCollector(report));
            }
            var result = ExitCodes.Success;
            foreach (var file in inputs)
            {
                var signatures = extractor.Extract(file);
                if (CheckEngine.Instance.RunAllRules(file, signatures, collectors, configuration) != RuleEngineResult.AllPass)
                {
                    result = ExitCodes.ChecksFailed;
                }
            }
            collectors.ForEach(c => c.Flush());
            return result;
        }

        static void ShowInvalidSuppression() => Console.Error.WriteLine("Invalid list of errors to suppress. Use -help for more information.");

        static void ShowHelp()
        {
            Console.Out.WriteLine(@"Authenticode Linter

Checks the Authenticode signature of your binaries.

Usage: authlint.exe -in ""C:\path to an\executable.exe""

    -in:            A path to an executable, DLL, or MSI to lint. Can be specified multiple times. Supports wildcards. Required.
    -suppress:      A comma separated list of error IDs to ignore. All checks are run if omitted. Optional.
    -q|quiet:       Run quietly and do not print anything to the output. Optional.
    -report:        A path to produce an XML file as a report. Optional.
    -verbose:       Show verbose output. Cannot be combined with -quiet.
    -revocation:    Specify how revocation checking is done. Valid values are none, offline, online. None is the default.

Exit codes:

    0:      All checks passed for all inputs, excluding any that were suppressed.
    1:      Invalid input or configuration was specified.
    2:      One or more checks failed, or the file is not Authenticode signed.
");
        }
    }

    internal static class ExitCodes
    {
        public static int Success { get; } = 0;
        public static int InvalidInputOrConfig { get; } = 1;
        public static int ChecksFailed { get; } = 2;
        public static int UnknownResults { get; } = 0xFF;
    }

    public enum RevocationChecking
    {
        None,
        Offline,
        Online
    }
}
