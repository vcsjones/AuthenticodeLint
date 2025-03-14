using AuthenticodeExaminer;
using AuthenticodeLint;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLintTests
{
    public class FakeSignature : ICmsSignature
    {
        private List<ICmsSignature> _nestedSignatures = new List<ICmsSignature>();

        public X509Certificate2Collection AdditionalCertificates { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public Oid DigestAlgorithm { get; set; }
        public Oid HashEncryptionAlgorithm { get; set; }
        public SignatureKind Kind { get; set; }
        public IReadOnlyList<CryptographicAttributeObject> SignedAttributes { get; set; }
        public IReadOnlyList<CryptographicAttributeObject> UnsignedAttributes { get; set; }
        public ReadOnlyMemory<byte> Signature => ReadOnlyMemory<byte>.Empty;

        public HashAlgorithmName DigestAlgorithmName => throw new System.NotImplementedException();

        public byte[] Content => throw new System.NotImplementedException();

        public byte[] SerialNumber => throw new System.NotImplementedException();

        public IReadOnlyList<ICmsSignature> GetNestedSignatures() => _nestedSignatures;

        public void Add(ICmsSignature signature) => _nestedSignatures.Add(signature);

        public FakeSignature()
        {
            var signed = new List<CryptographicAttributeObject>();
            var unsigned = new List<CryptographicAttributeObject>();
            SignedAttributes = signed;
            UnsignedAttributes = unsigned;
            var digest = new AsnEncodedData(new Oid(KnownOids.MessageDigest), new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });
            signed.Add(new CryptographicAttributeObject(new Oid(KnownOids.MessageDigest), new AsnEncodedDataCollection(digest)));
        }
    }
}
