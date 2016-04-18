using System.Collections.Generic;
using AuthenticodeLint.Rules;
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
            return (from type in typeof(IAuthenticodeRule).Assembly.GetExportedTypes()
                    where typeof(IAuthenticodeRule).IsAssignableFrom(type) && type.GetConstructor(Type.EmptyTypes) != null
                    let instance = (IAuthenticodeRule)Activator.CreateInstance(type)
                    orderby instance.RuleId
                    select instance
                    ).ToList();
        }

        public RuleEngineResult RunAllRules(string file, Graph<Signature> signatures, List<IRuleResultCollector> collectors, CheckConfiguration configuration)
        {
            var verbose = configuration.Verbose;
            var suppressedRuleIDs = configuration.SuppressErrorIDs;
            var rules = GetRules();
            var engineResult = RuleEngineResult.AllPass;
            collectors.ForEach(c => c.BeginSet(file));
            foreach(var rule in rules)
            {
                RuleResult result;
                var verboseWriter = verbose ? new VerboseSignatureLogger() : SignatureLogger.Null;
                if (signatures.Items.Count == 0)
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogMessage("File is not Authenticode signed.");
                }
                else
                {
                    if (suppressedRuleIDs.Contains(rule.RuleId))
                    {
                        result = RuleResult.Skip;
                    }
                    else if (rule is IAuthenticodeFileRule)
                    {
                        result = ((IAuthenticodeFileRule)rule).Validate(file, verboseWriter, configuration);
                    }
                    else if (rule is IAuthenticodeSignatureRule)
                    {
                        result = ((IAuthenticodeSignatureRule)rule).Validate(signatures, verboseWriter, configuration);
                    }
                    else
                    {
                        throw new NotSupportedException("Rule type is not supported.");
                    }
                }
                if (result != RuleResult.Pass)
                {
                    engineResult = RuleEngineResult.NotAllPass;
                }
                collectors.ForEach(c => c.CollectResult(rule, result, verboseWriter.Messages));
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
