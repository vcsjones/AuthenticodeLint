using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint
{
    public class Signature
    {
        public SignerInfo SignerInfo { get; }
        public X509Certificate2Collection AdditionalCertificates { get; }

        public Signature(SignerInfo signerInfo, X509Certificate2Collection additionalCertificates)
        {
            SignerInfo = signerInfo;
            AdditionalCertificates = additionalCertificates;
        }
    }
}
