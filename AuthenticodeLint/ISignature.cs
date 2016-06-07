using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint
{
    public interface ISignature
    {
        Oid DigestAlgorithm { get; }
        Oid HashEncryptionAlgorithm { get; }
        CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        CryptographicAttributeObjectCollection SignedAttributes { get; }
        X509Certificate2 Certificate { get; }
        IReadOnlyList<ISignature> GetNestedSignatures();
        SignatureKind Kind { get; }
        X509Certificate2Collection AdditionalCertificates { get; }
    }
}
