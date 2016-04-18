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
        RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }

    public interface IAuthenticodeFileRule : IAuthenticodeRule
    {
        RuleResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }
}
