using System.Collections.Generic;
using AuthenticodeLint.Rules;
using System.Security.Cryptography.Pkcs;
using System;

namespace AuthenticodeLint
{
    public class CheckEngine
    {
        static CheckEngine()
        {
            Instance = new CheckEngine();
        }

        public static CheckEngine Instance { get; }

        public IReadOnlyList<IAuthenticodeRule> GetRules()
        {
            return new List<IAuthenticodeRule>
            {
                new Sha1PrimarySignatureRule(),
                new Sha2SignatureExistsRule()
            };
        }

        public RuleEngineResult RunAllRules(string file, Graph<SignerInfo> signatures, List<IRuleResultCollector> collectors, HashSet<int> suppressedRuleIDs)
        {

            var rules = GetRules();
            var engineResult = RuleEngineResult.AllPass;
            collectors.ForEach(c => c.BeginSet(file));
            foreach(var rule in rules)
            {
                RuleResult result;
                if (suppressedRuleIDs.Contains(rule.RuleId))
                {
                    result = RuleResult.Skip;
                }
                else
                {
                    result = rule.Validate(signatures);
                    if (result != RuleResult.Pass)
                    {
                        engineResult = RuleEngineResult.NotAllPass;
                    }
                }
                collectors.ForEach(c => c.CollectResult(rule, result));
            }
            collectors.ForEach(c => c.CompleteSet());
            return engineResult;
        }
    }

    public interface IRuleResultCollector
    {
        void CollectResult(IAuthenticodeRule rule, RuleResult result);
        void BeginSet(string setName);
        void CompleteSet();
    }

    public class StdOutResultCollector : IRuleResultCollector
    {
        private string _setName;

        public void BeginSet(string setName)
        {
            _setName = setName;
            Console.Out.WriteLine($"Start checks for {_setName}.");
        }

        public void CollectResult(IAuthenticodeRule rule, RuleResult result)
        {
            if (_setName == null)
            {
                throw new InvalidOperationException("Cannot collect results for an unknown set.");
            }

            switch(result)
            {
                case RuleResult.Skip:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" was skipped because it was suppressed.");
                    break;
                case RuleResult.Fail:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" failed.");
                    break;
                case RuleResult.Pass:
                    Console.Out.WriteLine($"\tRule #{rule.RuleId} \"{rule.RuleName}\" passed.");
                    break;
            }
        }

        public void CompleteSet()
        {
            Console.Out.WriteLine($"Complete checks for {_setName}.");
        }
    }

    public enum RuleEngineResult
    {
        AllPass,
        NotAllPass
    }
}
