using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class Sha2SignatureExistsRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10001;

        public string RuleName { get; } = "SHA2 Signed";

        public string ShortDescription { get; } = "A SHA2 signature should exist.";

        public RuleSet RuleSet { get; } = RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ISignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            if (signatures.Any(s =>
                s.DigestAlgorithm.Value == KnownOids.SHA256 ||
                s.DigestAlgorithm.Value == KnownOids.SHA384 ||
                s.DigestAlgorithm.Value == KnownOids.SHA512))
            {
                return RuleResult.Pass;
            }
            return RuleResult.Fail;
        }
    }
}
