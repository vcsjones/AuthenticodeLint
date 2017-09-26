using System;

namespace AuthenticodeLint
{
    [Flags]
    public enum RuleSet : byte
    {
        Modern = 0x01,
        Compat = 0x02,
        All = 0xFF
    }
}
