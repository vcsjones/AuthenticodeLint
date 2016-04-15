using System;
using System.Linq;

namespace AuthenticodeLint.Rules
{
    public class WinCertificatePaddingRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10008;

        public string RuleName { get; } = "No WinCertificate Structure Padding";

        public string ShortDescription { get; } = "Checks for non-zero data after the signature.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration, string file)
        {
            var padding = CertificatePaddingExtractor.ExtractPadding(file);
            if (padding?.Any(p => p != 0) ?? false)
            {
                verboseWriter.LogMessage($"Non-zero data found after PKCS#7 structure: {Convert.ToBase64String(padding)}.");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
