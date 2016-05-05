using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticodeLint
{
    public static class HashHelpers
    {
        public static string GetHashForSignature(SignerInfo signature)
        {
            var digest = signature.SignatureDigest();
            var digestString = digest.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
            return digestString;
        }

        public static string HexEncode(byte[] data)
        {
            return data.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
        }
    }
}
