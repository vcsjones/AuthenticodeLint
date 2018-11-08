using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class SinglePrimarySignatureRule : IAuthenticodeSignatureRule
    {
        public int RuleId => 10014;

        public string RuleName => "Single primary signature";

        public string ShortDescription => "Limit to a single primary signature.";

        public RuleSet RuleSet => RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            if (graph.Count == 0)
            {
                return RuleResult.Fail;
            }
            if (graph.Count > 1)
            {
                verboseWriter.LogMessage("Multiple primary signatures exist.");
                return RuleResult.Fail;
            }
            return RuleResult.Pass;
        }
    }
}
