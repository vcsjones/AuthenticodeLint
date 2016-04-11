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
                new Sha2SignatureExistsRule(),
                new NoWeakFileDigestAlgorithmsRule()
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

    public enum RuleEngineResult
    {
        AllPass,
        NotAllPass
    }
}
