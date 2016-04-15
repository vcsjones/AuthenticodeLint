using System.Collections.Generic;
using AuthenticodeLint.Rules;

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
                new NoWeakFileDigestAlgorithmsRule(),
                new TimestampedRule(),
                new PublisherInformationPresentRule(),
                new PublisherInformationUrlHttpsRule(),
                new SigningCertificateDigestAlgorithmRule(),
                new TrustedSignatureRule(),
                new WinCertificatePaddingRule(),
                new NoUnknownUnsignedAttibuteRule(),
                new NoUnknownCertificatesRule()
            };
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
                    else
                    {
                        result = rule.Validate(signatures, verboseWriter, configuration, file);
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
