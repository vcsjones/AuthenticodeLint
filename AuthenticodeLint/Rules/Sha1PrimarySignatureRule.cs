using System.Linq;

namespace AuthenticodeLint.Rules
{
    public class Sha1PrimarySignatureRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10000;

        public string RuleName { get; } = "Primary SHA1";

        public string ShortDescription { get; } = "Primary signature should be SHA1.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration, string file)
        {
            var primary = graph.Items.SingleOrDefault()?.Node;
            //There are zero signatures.
            if (primary == null)
            {
                return RuleResult.Fail;
            }
            if (primary.SignerInfo.DigestAlgorithm.Value != KnownOids.SHA1)
            {
                verboseWriter.LogSignatureMessage(primary.SignerInfo, $"Expected {nameof(KnownOids.SHA1)} digest algorithm but is {primary.SignerInfo.DigestAlgorithm.FriendlyName}.");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
