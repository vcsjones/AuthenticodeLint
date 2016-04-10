namespace AuthenticodeLint
{
    interface IAuthenticodeRule
    {
        int RuleId { get; }
        bool Validate();
    }


}
