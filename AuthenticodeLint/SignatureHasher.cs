using AuthenticodeExaminer;
using System;
using System.Linq;
using System.Text;

namespace AuthenticodeLint
{
    public static class HashHelpers
    {
        public static string GetHashForSignature(ICmsSignature signature)
        {
            var digest = signature.SignatureDigest();
            return digest!.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
        }
    }
}
