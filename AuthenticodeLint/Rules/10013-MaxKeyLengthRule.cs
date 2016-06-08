using System;
using System.Collections.Generic;

namespace AuthenticodeLint.Rules
{
    public class MaxKeyLengthRule : IAuthenticodeSignatureRule
    {
        private const int MAX_ECDSA_KEY_SIZE = 384;
        private const int MAX_RSA_KEY_SIZE = 4096;
        private const int MAX_DSA_KEY_SIZE = 1024;

        public int RuleId { get; } = 10013;

        public string RuleName { get; } = "Maximum Key Length";

        public string ShortDescription { get; } = "Validates the maximum key length of a signing certificate.";

        public RuleResult Validate(IReadOnlyList<ISignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.Any);
            var result = RuleResult.Pass;
            foreach (var signature in signatures)
            {
                var keyInfo = BitStrengthCalculator.CalculateStrength(signature.Certificate);
                switch (keyInfo.AlgorithmName)
                {
                    case PublicKeyAlgorithm.ECDSA:
                        if (keyInfo.BitSize == null)
                        {
                            verboseWriter.LogSignatureMessage(signature, "Signature uses ECDSA with an unknown curve.");
                            result = RuleResult.Fail;
                        }
                        else if (keyInfo.BitSize > MAX_ECDSA_KEY_SIZE)
                        {
                            verboseWriter.LogSignatureMessage(signature, $"Signature uses ECDSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_ECDSA_KEY_SIZE}.");
                            result = RuleResult.Fail;
                        }
                        break;
                    case PublicKeyAlgorithm.RSA:
                        if (keyInfo.BitSize == null)
                        {
                            verboseWriter.LogSignatureMessage(signature, "Signature has an unknown RSA key size.");
                            result = RuleResult.Fail;
                        }
                        else if (keyInfo.BitSize > MAX_RSA_KEY_SIZE)
                        {
                            verboseWriter.LogSignatureMessage(signature, $"Signature uses RSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_RSA_KEY_SIZE}.");
                            result = RuleResult.Fail;
                        }
                        break;
                    case PublicKeyAlgorithm.DSA:
                        if (keyInfo.BitSize == null)
                        {
                            verboseWriter.LogSignatureMessage(signature, "Signature has an unknown DSA key size.");
                            result = RuleResult.Fail;
                        }
                        else if (keyInfo.BitSize > MAX_DSA_KEY_SIZE)
                        {
                            verboseWriter.LogSignatureMessage(signature, $"Signature uses DSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_DSA_KEY_SIZE}.");
                            result = RuleResult.Fail;
                        }
                        break;
                    case PublicKeyAlgorithm.Other:
                        goto default;
                    default:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses an unknown algorithm.");
                        result = RuleResult.Fail;
                        break;
                }
            }
            return result;
        }
    }
}
