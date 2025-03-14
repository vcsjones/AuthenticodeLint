using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class MaxKeyLengthRule : IAuthenticodeSignatureRule
    {
        private const int MAX_ECDSA_KEY_SIZE = 384;
        private const int MAX_RSA_KEY_SIZE = 4096;
        private const int MAX_DSA_KEY_SIZE = 1024;

        public int RuleId => 10013;

        public string RuleName => "Maximum Key Length";

        public string ShortDescription => "Validates the maximum key length of a signing certificate.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.Any, deep: true);
            var result = RuleResult.Pass;
            foreach (var signature in signatures)
            {
                var keyInfo = BitStrengthCalculator.CalculateStrength(signature.Certificate!);
                switch (keyInfo.AlgorithmName)
                {
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature uses ECDSA with an unknown curve.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize > MAX_ECDSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses ECDSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_ECDSA_KEY_SIZE}.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.ECDSA:
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown RSA key size.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize > MAX_RSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses RSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_RSA_KEY_SIZE}.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA:
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown DSA key size.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize > MAX_DSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses DSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_DSA_KEY_SIZE}.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.DSA:
                        break;
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
