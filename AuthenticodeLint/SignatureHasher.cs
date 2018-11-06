using AuthenticodeExaminer;
using System.Linq;
using System.Text;

namespace AuthenticodeLint
{
    public static class HashHelpers
    {
        public static string GetHashForSignature(ICmsSignature signature)
        {
            var digest = signature.SignatureDigest();
            var digestString = digest.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
            return digestString;
        }

        public static string HexEncode(byte[] data)
        {
            return data.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
        }

        public static string HexEncodeBigEndian(byte[] data)
        {
            return data.Aggregate(new StringBuilder(), (acc, b) => acc.Insert(0, string.Format("{0:x2}", b))).ToString();
        }
    }
}
