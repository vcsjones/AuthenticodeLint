using System.Collections.Generic;
using System.Linq;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class Sha2SignatureExistsRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10001;

        public string RuleName => "SHA2 Signed";

        public string ShortDescription => "A SHA2 signature should exist.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            if (signatures.Any(s =>
                s.DigestAlgorithm!.Value == KnownOids.SHA256 ||
                s.DigestAlgorithm.Value == KnownOids.SHA384 ||
                s.DigestAlgorithm.Value == KnownOids.SHA512))
            {
                return RuleResult.Pass;
            }
            return RuleResult.Fail;
        }
    }
}
