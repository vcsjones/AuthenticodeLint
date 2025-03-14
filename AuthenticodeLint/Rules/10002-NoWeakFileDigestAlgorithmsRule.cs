using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class NoWeakFileDigestAlgorithmsRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10002;

        public string RuleName => "No Weak File Digests";

        public string ShortDescription => "Checks for weak file digest algorithms.";

        public RuleSet RuleSet => RuleSet.All;
        
        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                if (signature.DigestAlgorithm!.Value == KnownOids.MD2)
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
