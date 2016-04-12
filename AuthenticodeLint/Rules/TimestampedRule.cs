using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class TimestampedRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10003;

        public string RuleName { get; } = "Timestamped Rule";

        public string ShortDescription { get; } = "Signatures should have a time stamped counter signer.";

        public unsafe RuleResult Validate(Graph<SignerInfo> graph)
        {
            var signatures = graph.VisitAll();
            foreach (var signature in signatures)
            {
                var isSigned = false;
                foreach (var attribute in signature.UnsignedAttributes)
                {
                    SignatureBase timeStampCounterSign = null;
                    if (attribute.Oid.Value == KnownOids.Rfc3161CounterSignature)
                    {
                        timeStampCounterSign = new Rfc3161Signature(attribute.Values[0]);
                    }
                    else if (attribute.Oid.Value == KnownOids.AuthenticodeCounterSignature)
                    {
                        timeStampCounterSign = new AuthenticodeSignature(attribute.Values[0]);
                    }
                    if (timeStampCounterSign == null)
                    {
                        continue;
                    }
                    if (timeStampCounterSign.DigestAlgorithm.Value == signature.DigestAlgorithm.Value)
                    {
                        isSigned = true;
                        break;
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
