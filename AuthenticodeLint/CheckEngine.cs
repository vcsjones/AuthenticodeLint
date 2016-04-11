using System.Collections.Generic;
using AuthenticodeLint.Rules;
using System.Security.Cryptography.Pkcs;
using System;
using System.Linq;

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

        public RuleEngineResult RunAllRules(IReadOnlyList<SignerInfo> signatures, List<IRuleResultCollector> collectors, IReadOnlyList<int> suppressedRuleIDs)
        {

            var rules = GetRules();
            var engineResult = RuleEngineResult.AllPass;
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
            return engineResult;
        }
    }

    public interface IRuleResultCollector
    {
        void CollectResult(IAuthenticodeRule rule, RuleResult result);
    }

    public class StdOutResultCollector : IRuleResultCollector
    {
        public void CollectResult(IAuthenticodeRule rule, RuleResult result)
        {
            switch(result)
            {
                case RuleResult.Skip:
                    Console.Out.WriteLine($"Rule #{rule.RuleId} \"{rule.RuleName}\" was skipped because it was suppressed.");
                    break;
                case RuleResult.Fail:
                    Console.Out.WriteLine($"Rule #{rule.RuleId} \"{rule.RuleName}\" failed.");
                    break;
                case RuleResult.Pass:
                    Console.Out.WriteLine($"Rule #{rule.RuleId} \"{rule.RuleName}\" passed.");
                    break;
            }
        }
    }

    public enum RuleEngineResult
    {
        AllPass,
        NotAllPass
    }
}
