using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class Sha2SignatureExistsRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10001;

        public string RuleName { get; } = "SHA2 Signed";

        public string ShortDescription { get; } = "A SHA2 signature should exist.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration, string file)
        {
            var signatures = graph.VisitAll();
            if (signatures.Any(s =>
                s.SignerInfo.DigestAlgorithm.Value == KnownOids.SHA256 ||
                s.SignerInfo.DigestAlgorithm.Value == KnownOids.SHA384 ||
                s.SignerInfo.DigestAlgorithm.Value == KnownOids.SHA512))
            {
                return RuleResult.Pass;
            }
            return RuleResult.Fail;
        }
    }
}
