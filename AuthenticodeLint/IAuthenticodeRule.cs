namespace AuthenticodeLint
{
    public interface IAuthenticodeRule
    {
        int RuleId { get; }
        bool Validate();
    }
}
