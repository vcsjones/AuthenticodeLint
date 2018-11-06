using System.Linq;
using System.Security.Cryptography;
using AuthenticodeExaminer;

namespace AuthenticodeLint
{
    public static class SignerInfoExtensions
    {
        public static byte[] SignatureDigest(this ICmsSignature signature)
        {
            return signature.SignedAttributes
                .Cast<CryptographicAttributeObject>()
                .FirstOrDefault(s => s.Oid.Value == KnownOids.MessageDigest)?.Values[0].RawData;
        }
    }
}
