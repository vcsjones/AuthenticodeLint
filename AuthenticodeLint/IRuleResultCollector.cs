using AuthenticodeLint.Rules;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public interface IRuleResultCollector
    {
        void CollectResult(IAuthenticodeRule rule, RuleResult result, IReadOnlyList<string> additionalOutput);
        void BeginSet(string setName);
        void CompleteSet();
        void Flush();
    }
}
