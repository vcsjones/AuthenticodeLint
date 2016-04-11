using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class Sha1PrimarySignatureRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10000;

        public string RuleName { get; } = "Primary SHA1";

        public string ShortDescription { get; } = "Primary signature should be SHA1.";

        public RuleResult Validate(Graph<SignerInfo> signatures)
        {
            var primary = signatures.Items.SingleOrDefault()?.Node;
            //There are zero signatures.
            if (primary == null)
            {
                return RuleResult.Fail;
            }
            return primary.DigestAlgorithm.Value == KnownOids.SHA1 ? RuleResult.Pass : RuleResult.Fail;
        }
    }
}
