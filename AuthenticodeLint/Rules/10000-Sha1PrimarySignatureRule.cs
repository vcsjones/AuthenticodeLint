using System.Collections.Generic;
using System.Linq;

namespace AuthenticodeLint.Rules
{
    public class Sha1PrimarySignatureRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10000;

        public string RuleName { get; } = "Primary SHA1";

        public string ShortDescription { get; } = "Primary signature should be SHA1.";

        public RuleSet RuleSet { get; } = RuleSet.Compat;

        public RuleResult Validate(IReadOnlyList<ISignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            if (graph.Count == 0)
            {
                return RuleResult.Fail;
            }
            if (graph.Count > 1)
            {
                verboseWriter.LogMessage("Multiple primary signatures exist.");
                return RuleResult.Fail;
            }
            var primary = graph[0];
            if (primary.DigestAlgorithm.Value != KnownOids.SHA1)
            {
                verboseWriter.LogSignatureMessage(primary, $"Expected {nameof(KnownOids.SHA1)} digest algorithm but is {primary.DigestAlgorithm.FriendlyName}.");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
