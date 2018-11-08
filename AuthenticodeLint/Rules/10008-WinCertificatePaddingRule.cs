using System;
using System.Linq;
using System.Numerics;

namespace AuthenticodeLint.Rules
{
    public class WinCertificatePaddingRule : IAuthenticodeFileRule
    {
        public int RuleId => 10008;

        public string RuleName => "No WinCertificate Structure Padding";

        public string ShortDescription => "Checks for non-zero data after the signature.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var padding = CertificatePaddingExtractor.ExtractPadding(file);
            if (padding?.Any(p => p != 0) == true)
            {
                verboseWriter.LogMessage($"Non-zero data found after PKCS#7 structure: {Convert.ToBase64String(padding)}.");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
