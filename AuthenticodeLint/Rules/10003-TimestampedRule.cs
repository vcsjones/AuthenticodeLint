using System;
using System.Collections.Generic;
using System.Linq;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class TimestampedRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10003;

        public string RuleName => "Timestamped Rule";

        public string ShortDescription => "Signatures should have a timestamp counter signer.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var pass = true;
            foreach (var signature in signatures)
            {
                var counterSignatures = signature.VisitAll(SignatureKind.AnyCounterSignature).ToList();
                var isSigned = false;
                var strongSign = false;
                foreach (var counterSignature in counterSignatures)
                {
                    isSigned = true;
                    if (counterSignature.DigestAlgorithm!.Value == signature.DigestAlgorithm!.Value)
                    {
                        strongSign = true;
                        break;
                    }
                }
                if (!isSigned && strongSign)
                {
                    throw new InvalidOperationException("Unexpectedly have a strong signature.");
                }
                if (!isSigned)
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature is not timestamped.");
                    pass = false;
                }
                else if (!strongSign)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Signature is not timestamped with the expected hash algorithm {signature.DigestAlgorithm!.FriendlyName}.");
                    pass = false;
                }
            }
            return pass ? RuleResult.Pass : RuleResult.Fail;
        }
    }
}
