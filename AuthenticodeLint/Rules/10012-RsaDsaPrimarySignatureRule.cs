using System.Collections.Generic;
using System.Linq;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class RsaDsaPrimarySignatureRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10012;

        public string RuleName => "RSA/DSA Primary Signature";

        public string ShortDescription => "Primary signature should be RSA or DSA.";

        public RuleSet RuleSet => RuleSet.Compat;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var primary = graph.FirstOrDefault();
            //There are zero signatures.
            if (primary == null)
            {
                return RuleResult.Fail;
            }
            var info = BitStrengthCalculator.CalculateStrength(primary.Certificate!);
            if (info.AlgorithmName != PublicKeyAlgorithm.RSA && info.AlgorithmName != PublicKeyAlgorithm.DSA)
            {
                verboseWriter.LogSignatureMessage(primary, $"Primary signature should use RSA or DSA key but uses {info.AlgorithmName.ToString()}");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
