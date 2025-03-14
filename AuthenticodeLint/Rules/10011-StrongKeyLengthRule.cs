using System;
using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class StrongKeyLengthRule : IAuthenticodeSignatureRule
    {
        private const int MIN_RSADSA_KEY_SIZE = 2048;
        private const int MIN_ECDSA_KEY_SIZE = 256;

        public int RuleId => 10011;

        public string RuleName => "Strong Key Length";

        public string ShortDescription => "Validates the key length of a signing certificate.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.Any | SignatureKind.Any);
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
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize < MIN_ECDSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses a ECDSA key of size {keyInfo.BitSize} which is below the recommended {MIN_ECDSA_KEY_SIZE}.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.ECDSA:
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown RSA key size.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize < MIN_RSADSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses a RSA key of size {keyInfo.BitSize} which is below the recommended {MIN_RSADSA_KEY_SIZE}.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize >= MIN_RSADSA_KEY_SIZE:
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown DSA key size.");
                        result = RuleResult.Fail;
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize < MIN_RSADSA_KEY_SIZE:
                        //Effectively, 1024 is the max for a DSA key, so this will likely always fail.
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses a DSA key of size {keyInfo.BitSize} which is below the recommended {MIN_RSADSA_KEY_SIZE}.");
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
