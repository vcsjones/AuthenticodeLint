﻿using AuthenticodeExaminer;
using System.Collections.Generic;

namespace AuthenticodeLint.Rules
{
    public interface IAuthenticodeRule
    {
        int RuleId { get; }
        string ShortDescription { get; }
        string RuleName { get; }
        RuleSet RuleSet { get; }
    }

    public interface IAuthenticodeSignatureRule : IAuthenticodeRule
    {
        RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }

    public interface IAuthenticodeFileRule : IAuthenticodeRule
    {
        RuleResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }
}
