﻿using System.Collections.Generic;
using System.Linq;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class NoUnknownUnsignedAttibuteRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10009;

        public string RuleName => "No Unknown Unsigned Attributes";

        public string ShortDescription => "Checks for the presence of unsigned attributes with unknown an OID.";

        public RuleSet RuleSet => RuleSet.All;

        private static string[] _trustedUnsignedAttributes = new[]
        {
            KnownOids.AuthenticodeCounterSignature,
            KnownOids.Rfc3161CounterSignature,
            KnownOids.NestedSignatureOid,
            KnownOids.SealingSignature,
            KnownOids.SealingTimestamp
        };

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                var counterSignatures = signature.VisitAll(SignatureKind.AnyCounterSignature);
                foreach(var counterSignature in counterSignatures)
                {
                    foreach (var attribute in counterSignature.UnsignedAttributes)
                    {
                        if (!_trustedUnsignedAttributes.Contains(attribute.Oid.Value))
                        {
                            result = RuleResult.Fail;
                            var displayName = attribute.Oid.FriendlyName ?? "<no friendly name>";
                            verboseWriter.LogSignatureMessage(signature, $"Signature contains counter signer with unknown unsigned attribute {displayName} ({attribute.Oid.Value}).");
                        }
                    }
                }
                foreach(var attribute in signature.UnsignedAttributes)
                {
                    if (!_trustedUnsignedAttributes.Contains(attribute.Oid.Value))
                    {
                        result = RuleResult.Fail;
                        var displayName = attribute.Oid.FriendlyName ?? "<no friendly name>";
                        verboseWriter.LogSignatureMessage(signature, $"Signature contains unknown unsigned attribute {displayName} ({attribute.Oid.Value}).");
                    }
                }
            }
            return result;
        }
    }
}
