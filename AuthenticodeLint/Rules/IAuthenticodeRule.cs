using System.Collections.Generic;

namespace AuthenticodeLint.Rules
{
    public interface IAuthenticodeRule
    {
        int RuleId { get; }
        string ShortDescription { get; }
        string RuleName { get; }
    }

    public interface IAuthenticodeSignatureRule : IAuthenticodeRule
    {
        RuleResult Validate(IReadOnlyList<ISignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }

    public interface IAuthenticodeFileRule : IAuthenticodeRule
    {
        RuleResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }
}
