using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class TrustedSignatureRule : IAuthenticodeFileRule
    {
        public int RuleId => 10007;

        public string RuleName => "Valid Signature";

        public string ShortDescription => "Validates the file has correct signatures.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var inspector = new FileInspector(file);
            var result = inspector.Validate(configuration.RevocationMode);
            if (result == SignatureCheckResult.Valid)
            {
                return RuleResult.Pass;
            }
            verboseWriter.LogMessage($"Authenticode signature validation failed with '{result}'.");
            return RuleResult.Fail;
        }
    }
}
