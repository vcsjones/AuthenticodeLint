using System.Collections.Generic;
using AuthenticodeLint.Rules;
using System;
using System.Linq;
using AuthenticodeExaminer;

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
            return
            [
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
                new StrongKeyLengthRule(),
                new RsaDsaPrimarySignatureRule(),
                new MaxKeyLengthRule(),
                new SinglePrimarySignatureRule(),
                new NoSha1Rule(),
            ];
        }

        public RuleEngineResult RunAllRules(string file, IReadOnlyList<ICmsSignature> signatures, List<IRuleResultCollector> collectors, CheckConfiguration configuration)
        {
            var verbose = configuration.Verbose;
            var suppressedRuleIDs = configuration.SuppressErrorIDs;
            var rules = GetRules();
            var engineResult = RuleEngineResult.AllPass;
            collectors.ForEach(c => c.BeginSet(file));
            foreach(var rule in rules)
            {
                RuleResult result;
                var verboseWriter = verbose ? new MemorySignatureLogger() : SignatureLogger.Null;
                if (signatures.Count == 0)
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
                    else if ((rule.RuleSet & configuration.RuleSet) == 0)
                    {
                        result = RuleResult.Excluded;
                    }
                    else
                    {
                        result = rule switch
                        {
                            IAuthenticodeFileRule fileRule => fileRule.Validate(file, verboseWriter, configuration),
                            IAuthenticodeSignatureRule sigRule => sigRule.Validate(signatures, verboseWriter, configuration),
                            _ => throw new NotSupportedException("Rule type is not supported."),
                        };
                    }
                }
                if (result == RuleResult.Fail)
                {
                    engineResult = RuleEngineResult.NotAllPass;
                }
                collectors.ForEach(c => c.CollectResult(rule, result, verboseWriter.Messages));
            }
            if (configuration.ExtractPath != null)
            {
                Extraction.ExtractToDisk(file, configuration, signatures);
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
