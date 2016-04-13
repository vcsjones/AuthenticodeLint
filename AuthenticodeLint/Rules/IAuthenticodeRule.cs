using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public interface IAuthenticodeRule
    {
        int RuleId { get; }
        string ShortDescription { get; }
        string RuleName { get; }
        RuleResult Validate(Graph<SignerInfo> graph, SignatureLoggerBase verboseWriter);
    }
}
