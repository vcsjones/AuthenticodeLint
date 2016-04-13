using System.Security.Cryptography.Pkcs;
using System.Linq;
using System.Security.Cryptography;

namespace AuthenticodeLint
{
    public static class SignerInfoExtensions
    {
        public static byte[] SignatureDigest(this SignerInfo signature)
        {
            return signature.SignedAttributes
                .Cast<CryptographicAttributeObject>()
                .FirstOrDefault(s => s.Oid.Value == KnownOids.MessageDigest)?.Values[0].RawData;
        }
    }
}
