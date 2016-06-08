using AuthenticodeLint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLintTests
{
    public class FakeSignature : ISignature
    {
        private List<ISignature> _nestedSignatures = new List<ISignature>();

        public X509Certificate2Collection AdditionalCertificates { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public Oid DigestAlgorithm { get; set; }
        public Oid HashEncryptionAlgorithm { get; set; }
        public SignatureKind Kind { get; set; }
        public CryptographicAttributeObjectCollection SignedAttributes { get; set; }
        public CryptographicAttributeObjectCollection UnsignedAttributes { get; set; }
        public IReadOnlyList<ISignature> GetNestedSignatures() => _nestedSignatures;

        public void Add(ISignature signature) => _nestedSignatures.Add(signature);

        public FakeSignature()
        {
            SignedAttributes = new CryptographicAttributeObjectCollection();
            UnsignedAttributes = new CryptographicAttributeObjectCollection();
            SignedAttributes.Add(new AsnEncodedData(new Oid(KnownOids.MessageDigest), new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }));
        }
    }
}
