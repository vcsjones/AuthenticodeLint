using AuthenticodeLint.Rules;
using System;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class StdOutRuleResultCollector : IRuleResultCollector
    {
        private string _setName;

        public void BeginSet(string setName)
        {
            _setName = setName;
            Console.Out.WriteLine($"Start checks for {_setName}.");
        }

        public void CollectResult(IAuthenticodeRule rule, RuleResult result, IReadOnlyList<string> additionalOutput)
        {
            if (_setName == null)
            {
                throw new InvalidOperationException("Cannot collect results for an unknown set.");
            }

            switch (result)
            {
                case RuleResult.Skip:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" was skipped because it was suppressed.");
                    break;
                case RuleResult.Excluded:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" was excluded because it is not part of the ruleset.");
                    break;
                case RuleResult.Fail:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" failed.");
                    break;
                case RuleResult.Pass:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" passed.");
                    break;
            }
            foreach(var message in additionalOutput)
            {
                Console.Out.WriteLine("\t\t" + message);
            }
        }

        public void CompleteSet()
        {
            Console.Out.WriteLine($"Complete checks for {_setName}.");
            _setName = null;
        }

        public void Flush()
        {
        }
    }
}
