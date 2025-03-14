using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class Sha1PrimarySignatureRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10000;

        public string RuleName => "Primary SHA1";

        public string ShortDescription => "Primary signature should be SHA1.";

        public RuleSet RuleSet => RuleSet.Compat;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            if (graph.Count == 0)
            {
                return RuleResult.Fail;
            }
            var primary = graph[0];
            if (primary.DigestAlgorithm!.Value != KnownOids.SHA1)
            {
                verboseWriter.LogSignatureMessage(primary, $"Expected {nameof(KnownOids.SHA1)} digest algorithm but is {primary.DigestAlgorithm.FriendlyName}.");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
