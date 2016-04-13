using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class NoWeakFileDigestAlgorithmsRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10002;

        public string RuleName { get; } = "No Weak File Digests";

        public string ShortDescription { get; } = "Checks for weak file digest algorithms.";

        public RuleResult Validate(Graph<SignerInfo> graph, SignatureLoggerBase verboseWriter)
        {
            var signatures = graph.VisitAll();
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                if (signature.DigestAlgorithm.Value == KnownOids.MD2)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.MD2)} digest algorithm.");
                    result = RuleResult.Fail;
                }
                else if (signature.DigestAlgorithm.Value == KnownOids.MD4)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.MD4)} digest algorithm.");
                    result = RuleResult.Fail;
                }
                else if (signature.DigestAlgorithm.Value == KnownOids.MD5)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.MD5)} digest algorithm.");
                    result = RuleResult.Fail;
                }
            }
            return result;
        }
    }
}
