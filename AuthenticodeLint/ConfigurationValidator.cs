using AuthenticodeExaminer;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AuthenticodeLint
{
    public class CheckConfiguration
    {
        public IReadOnlyList<string> InputPaths { get; }
        public string? ReportPath { get; }
        public bool Quiet { get; }
        public HashSet<int> SuppressErrorIDs { get; }
        public bool Verbose { get; }
        public RevocationChecking RevocationMode {get;}
        public string? ExtractPath { get; }
        public RuleSet RuleSet { get; }

        public CheckConfiguration(IReadOnlyList<string> inputPaths, string? reportPath, bool quiet, HashSet<int> suppressErrorIDs, bool verbose, RevocationChecking revocationMode, string? extract, RuleSet ruleSet)
        {
            InputPaths = inputPaths;
            ReportPath = reportPath;
            Quiet = quiet;
            SuppressErrorIDs = suppressErrorIDs;
            Verbose = verbose;
            RevocationMode = revocationMode;
            ExtractPath = extract;
            RuleSet = ruleSet;
        }
    }

    public static class ConfigurationValidator
    {
        //Does its best to validate the configuration, such as the path actually existing, etc.
        public static bool ValidateAndPrint(CheckConfiguration configuration, TextWriter printer)
        {
            bool success = true;
            if (configuration.Verbose && configuration.Quiet)
            {
                printer.WriteLine("Cannot combine verbose and quiet configuration.");
                success = false;
            }
            foreach (var path in configuration.InputPaths)
            {
                if (!File.Exists(path))
                {
                    printer.WriteLine($"The input path {path} does not exist.");
                    success = false;
                }
            }
            var rules = CheckEngine.Instance.GetRules();
            foreach (var suppression in configuration.SuppressErrorIDs)
            {
                if (!rules.Any(r => r.RuleId == suppression))
                {
                    printer.WriteLine($"Error {suppression} is not a valid ID.");
                    success = false;
                }
            }
            if (configuration.ExtractPath != null)
            {
                if (!Directory.Exists(configuration.ExtractPath))
                {
                    printer.WriteLine($"Directory {configuration.ExtractPath} does not exist.");
                }
            }
            return success;
        }
    }

}
