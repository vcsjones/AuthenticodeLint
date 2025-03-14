using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class NoSha1Rule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10015;

        public string RuleName => "No Weak File Digests";

        public string ShortDescription => "Checks for weak file digest algorithms.";

        public RuleSet RuleSet => RuleSet.Modern;
        
        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                if (signature.DigestAlgorithm!.Value == KnownOids.SHA1)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.SHA1)} digest algorithm.");
                    result = RuleResult.Fail;
                }
            }
            return result;
        }
    }
}
