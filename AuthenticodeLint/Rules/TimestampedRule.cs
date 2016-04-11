using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class TimestampedRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10003;

        public string RuleName { get; } = "Timestamped Rule";

        public string ShortDescription { get; } = "Signatures should have a time stamped counter signer.";

        public RuleResult Validate(Graph<SignerInfo> graph)
        {
            var signatures = graph.VisitAll();
            foreach(var signature in signatures)
            {
                var isSigned = false;
                foreach(var attribute in signature.UnsignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.AuthenticodeCounterSignature || attribute.Oid.Value == KnownOids.RFC3161CounterSignature)
                    {
                        isSigned = true;
                    }
                }
                if (!isSigned)
                {
                    return RuleResult.Fail;
                }
            }
            return RuleResult.Pass;
        }
    }
}
