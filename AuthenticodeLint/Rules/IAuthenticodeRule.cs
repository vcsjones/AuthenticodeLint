namespace AuthenticodeLint.Rules
{
    public interface IAuthenticodeRule
    {
        int RuleId { get; }
        string ShortDescription { get; }
        string RuleName { get; }
        RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration, string file);
    }
}
