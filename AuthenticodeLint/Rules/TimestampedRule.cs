using System;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class TimestampedRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10003;

        public string RuleName { get; } = "Timestamped Rule";

        public string ShortDescription { get; } = "Signatures should have a time stamped counter signer.";

        public unsafe RuleResult Validate(Graph<SignerInfo> graph, SignatureLoggerBase verboseWriter)
        {
            var signatures = graph.VisitAll();
            var pass = true;
            foreach (var signature in signatures)
            {
                var isSigned = false;
                var strongSign = false;
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
                    isSigned = true;
                    if (timeStampCounterSign.DigestAlgorithm.Value == signature.DigestAlgorithm.Value)
                    {
                        strongSign = true;
                        break;
                    }
                }
                if (!isSigned && strongSign)
                {
                    throw new InvalidOperationException("Unexpectedly have a strong signature.");
                }
                if (!strongSign)
                {
                    verboseWriter.LogMessage(signature, $"Signature is not timestamped with the expected hash algorithm {signature.DigestAlgorithm.FriendlyName}.");
                    pass = false;
                }
                if (!isSigned)
                {
                    verboseWriter.LogMessage(signature, $"Signature is not timestamped.");
                    pass = false;
                }
            }
            return pass ? RuleResult.Pass : RuleResult.Fail;
        }
    }
}
