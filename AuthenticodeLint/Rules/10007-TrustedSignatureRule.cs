using AuthenticodeExaminer;
using AuthenticodeLint.Interop;
using System;
using System.Runtime.InteropServices;

namespace AuthenticodeLint.Rules
{
    public class TrustedSignatureRule : IAuthenticodeFileRule
    {
        public int RuleId { get; } = 10007;

        public string RuleName { get; } = "Valid Signature";

        public string ShortDescription { get; } = "Validates the file has correct signatures.";

        public RuleSet RuleSet { get; } = RuleSet.All;

        public unsafe RuleResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var inspector = new FileInspector(file);
            var result = inspector.Validate(configuration.RevocationMode);
            if (result == SignatureCheckResult.Valid)
            {
                return RuleResult.Pass;
            }
            return RuleResult.Fail;
        }
    }
}
