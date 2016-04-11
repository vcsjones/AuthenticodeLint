using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AuthenticodeLint
{
    public class CheckConfiguration
    {
        public string InputPath { get; }
        public string ReportPath { get; }
        public bool Quiet { get; }
        public IReadOnlyList<int> SuppressErrorIDs { get; }

        public CheckConfiguration(string inputPath, string reportPath, bool quiet, IReadOnlyList<int> suppressErrorIDs)
        {
            InputPath = inputPath;
            ReportPath = reportPath;
            Quiet = quiet;
            SuppressErrorIDs = suppressErrorIDs;
        }
    }

    public static class ConfigurationValidator
    {
        //Does its best to validate the configuration, such as the path actually existing, etc.
        public static bool ValidateAndPrint(CheckConfiguration configuration, TextWriter printer)
        {
            bool success = true;
            if (!File.Exists(configuration.InputPath))
            {
                printer.WriteLine($"The input path ${configuration.InputPath} does not exist.");
                success = false;
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
            return success;
        }
    }

}
