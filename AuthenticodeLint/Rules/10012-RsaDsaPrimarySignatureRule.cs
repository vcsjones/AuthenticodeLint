using System;
using System.Linq;

namespace AuthenticodeLint.Rules
{
    public class RsaDsaPrimarySignatureRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10012;

        public string RuleName { get; } = "RSA/DSA Primary Signature";

        public string ShortDescription { get; } = "Primary signature should be RSA or DSA.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var primary = graph.SingleOrDefault()?.Node;
            //There are zero signatures.
            if (primary == null)
            {
                return RuleResult.Fail;
            }
            var info = BitStrengthCalculator.CalculateStrength(primary.SignerInfo.Certificate);
            if (info.AlgorithmName != PublicKeyAlgorithm.RSA && info.AlgorithmName != PublicKeyAlgorithm.DSA)
            {
                verboseWriter.LogSignatureMessage(primary.SignerInfo, $"Primary signature should use RSA or DSA key but uses ${info.AlgorithmName.ToString()}");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
