using AuthenticodeExaminer;
using System;

namespace AuthenticodeLint
{
    public static class HashHelpers
    {
        public static string GetHashForSignature(ICmsSignature signature)
        {
            var digest = signature.SignatureDigest();
            return digest is null ? string.Empty : Convert.ToHexString(digest);
        }
    }
}
