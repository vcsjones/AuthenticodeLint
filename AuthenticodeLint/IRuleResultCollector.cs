using AuthenticodeLint.Rules;

namespace AuthenticodeLint
{
    public interface IRuleResultCollector
    {
        void CollectResult(IAuthenticodeRule rule, RuleResult result);
        void BeginSet(string setName);
        void CompleteSet();
        void Flush();
    }
}
