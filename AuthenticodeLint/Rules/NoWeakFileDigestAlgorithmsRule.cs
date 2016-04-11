using System;
using System.Linq;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class NoWeakFileDigestAlgorithmsRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10002;

        public string RuleName { get; } = "Weak File Digest";

        public string ShortDescription { get; } = "Checks for weak file digest algorithms.";

        public RuleResult Validate(Graph<SignerInfo> graph)
        {
            var signatures = graph.VisitAll();
            if (signatures.Any(s =>
                s.DigestAlgorithm.Value == KnownOids.MD5 ||
                s.DigestAlgorithm.Value == KnownOids.MD4 ||
                s.DigestAlgorithm.Value == KnownOids.MD2))
            {
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
