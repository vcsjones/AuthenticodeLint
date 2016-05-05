namespace AuthenticodeLint.Rules
{
    public class NoWeakFileDigestAlgorithmsRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10002;

        public string RuleName { get; } = "No Weak File Digests";

        public string ShortDescription { get; } = "Checks for weak file digest algorithms.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll();
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                var signatureInfo = signature.SignerInfo;
                if (signatureInfo.DigestAlgorithm.Value == KnownOids.MD2)
                {
                    verboseWriter.LogSignatureMessage(signatureInfo, $"Uses the {nameof(KnownOids.MD2)} digest algorithm.");
                    result = RuleResult.Fail;
                }
                else if (signatureInfo.DigestAlgorithm.Value == KnownOids.MD4)
                {
                    verboseWriter.LogSignatureMessage(signatureInfo, $"Uses the {nameof(KnownOids.MD4)} digest algorithm.");
                    result = RuleResult.Fail;
                }
                else if (signatureInfo.DigestAlgorithm.Value == KnownOids.MD5)
                {
                    verboseWriter.LogSignatureMessage(signatureInfo, $"Uses the {nameof(KnownOids.MD5)} digest algorithm.");
                    result = RuleResult.Fail;
                }
            }
            return result;
        }
    }
}
