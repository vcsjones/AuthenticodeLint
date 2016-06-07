using AuthenticodeLint.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;

namespace AuthenticodeLint
{
    public interface ISignature
    {
        Oid Oid { get; }
        Oid DigestAlgorithm { get; }
        Oid HashEncryptionAlgorithm { get; }
        CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        CryptographicAttributeObjectCollection SignedAttributes { get; }
        X509Certificate2 Certificate { get; }
    }
    public abstract class CounterSignatureBase : ISignature
    {

        protected CounterSignatureBase(AsnEncodedData data)
        {
            Oid = data.Oid;
        }

        public Oid Oid { get; }

        public abstract Oid DigestAlgorithm { get; }
        public abstract Oid HashEncryptionAlgorithm { get; }
        public abstract CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        public abstract CryptographicAttributeObjectCollection SignedAttributes { get; }
        public abstract byte[] SerialNumber { get; }
        public abstract X509Certificate2 Certificate { get; }

        internal byte[] ReadBlob(CRYPTOAPI_BLOB blob)
        {
            var buffer = new byte[blob.cbData];
            Marshal.Copy(blob.pbData, buffer, 0, buffer.Length);
            return buffer;
        }

        internal unsafe CryptographicAttributeObjectCollection ReadAttributes(CRYPT_ATTRIBUTES attributes)
        {
            var collection = new CryptographicAttributeObjectCollection();
            var attributeSize = Marshal.SizeOf<CRYPT_ATTRIBUTE>();
            var blobSize = Marshal.SizeOf<CRYPTOAPI_BLOB>();
            for (var i = 0; i < attributes.cAttr; i++)
            {
                var structure = Marshal.PtrToStructure<CRYPT_ATTRIBUTE>(attributes.rgAttr + (i * attributeSize));
                var asnValues = new AsnEncodedDataCollection();
                for (var j = 0; j < structure.cValue; j++)
                {
                    var blob = Marshal.PtrToStructure<CRYPTOAPI_BLOB>(structure.rgValue + j * blobSize);
                    asnValues.Add(new AsnEncodedData(structure.pszObjId, ReadBlob(blob)));
                }
                collection.Add(new CryptographicAttributeObject(new Oid(structure.pszObjId), asnValues));
            }
            return collection;
        }

        protected X509Certificate2 FindCertificate(X509IssuerSerial issuerSerial, X509Certificate2Collection certificateCollection)
        {
            var byDN = certificateCollection.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
            if (byDN.Count < 1)
            {
                return null;
            }
            var bySerial = byDN.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
            if (bySerial.Count != 1)
            {
                return null;
            }
            return bySerial[0];
        }

        protected X509Certificate2 FindCertificate(string keyId, X509Certificate2Collection certificateCollection)
        {
            var byKeyId = certificateCollection.Find(X509FindType.FindBySubjectKeyIdentifier, keyId, false);
            if (byKeyId.Count != 1)
            {
                return null;
            }
            return byKeyId[0];
        }

        internal X509Certificate2Collection GetCertificatesFromMessage(CryptMsgSafeHandle handle)
        {
            var size = 0u;
            var certs = new X509Certificate2Collection();
            if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_COUNT_PARAM, 0, LocalBufferSafeHandle.Zero, ref size))
            {
                return certs;
            }
            uint certCount;
            using (var certCountLocalBuffer = LocalBufferSafeHandle.Alloc(size))
            {
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_COUNT_PARAM, 0, certCountLocalBuffer, ref size))
                {
                    return null;
                }
                certCount = unchecked((uint)Marshal.ReadInt32(certCountLocalBuffer.DangerousGetHandle(), 0));
            }
            if (certCount == 0)
            {
                return certs;
            }
            for (var i = 0u; i < certCount; i++)
            {
                uint certSize = 0;
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_PARAM, i, LocalBufferSafeHandle.Zero, ref certSize))
                {
                    continue;
                }
                using (var certLocalBuffer = LocalBufferSafeHandle.Alloc(certSize))
                {
                    if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_PARAM, i, certLocalBuffer, ref certSize))
                    {
                        continue;
                    }
                    var data = new byte[certSize];
                    Marshal.Copy(certLocalBuffer.DangerousGetHandle(), data, 0, data.Length);
                    var cert = new X509Certificate2(data);
                    certs.Add(cert);
                }
            }
            return certs;
        }
    }

    public class AuthenticodeSignature : CounterSignatureBase
    {

        public override Oid DigestAlgorithm { get; }
        public override Oid HashEncryptionAlgorithm { get; }
        public override CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        public override CryptographicAttributeObjectCollection SignedAttributes { get; }
        public override byte[] SerialNumber { get; }

        public override X509Certificate2 Certificate { get; }

        public unsafe AuthenticodeSignature(AsnEncodedData data) : base(data)
        {
            fixed (byte* dataPtr = data.RawData)
            {
                uint size = 0;
                LocalBufferSafeHandle localBuffer;
                if (Crypt32.CryptDecodeObjectEx(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, (IntPtr)500, new IntPtr(dataPtr), (uint)data.RawData.Length, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out localBuffer, ref size))
                {
                    using (localBuffer)
                    {
                        var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(localBuffer.DangerousGetHandle());
                        DigestAlgorithm = new Oid(signerInfo.HashAlgorithm.pszObjId);
                        HashEncryptionAlgorithm = new Oid(signerInfo.HashEncryptionAlgorithm.pszObjId);
                        SerialNumber = ReadBlob(signerInfo.SerialNumber);
                        UnsignedAttributes = ReadAttributes(signerInfo.UnauthAttrs);
                        SignedAttributes = ReadAttributes(signerInfo.AuthAttrs);
                    }
                }
                else
                {
                    throw new InvalidOperationException("Failed to read Authenticode signature");
                }
            }
        }
    }

    public class Rfc3161Signature : CounterSignatureBase
    {
        public override Oid DigestAlgorithm { get; }
        public override Oid HashEncryptionAlgorithm { get; }
        public override CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        public override CryptographicAttributeObjectCollection SignedAttributes { get; }
        public override byte[] SerialNumber { get; }
        public X509Store Certificates { get; }
        public override X509Certificate2 Certificate { get; }


        public unsafe Rfc3161Signature(AsnEncodedData data) : base(data)
        {
            if (data.Oid.Value != KnownOids.Rfc3161CounterSignature)
            {
                throw new ArgumentException("Data is not an RFC3161 signature.", nameof(data));
            }
            fixed (byte* pin = data.RawData)
            {
                EncodingType encodingType;
                CryptQueryContentType contentType;
                CryptQueryFormatType formatType;
                CertStoreSafeHandle store;
                CryptMsgSafeHandle msgHandle;
                var blob = new CRYPTOAPI_BLOB
                {
                    cbData = (uint)data.RawData.Length,
                    pbData = new IntPtr(pin)
                };
                var result = Crypt32.CryptQueryObject(
                    CryptQueryObjectType.CERT_QUERY_OBJECT_BLOB,
                    ref blob,
                    CryptQueryContentFlagType.CERT_QUERY_CONTENT_FLAG_ALL,
                    CryptQueryFormatFlagType.CERT_QUERY_FORMAT_FLAG_BINARY,
                    CryptQueryObjectFlags.NONE,
                    out encodingType,
                    out contentType,
                    out formatType,
                    out store,
                    out msgHandle,
                    IntPtr.Zero);
                if (!result)
                {
                    store.Dispose();
                    msgHandle.Dispose();
                    throw new InvalidOperationException("Unable to read signature.");
                }
                try
                {
                    Certificates = new X509Store(store.DangerousGetHandle());
                    var size = 0u;
                    if (!Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, LocalBufferSafeHandle.Zero, ref size))
                    {
                        Certificates.Dispose();
                        throw new InvalidOperationException("Unable to read signer information.");
                    }
                    var localBuffer = LocalBufferSafeHandle.Alloc(size);
                    if (!Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, localBuffer, ref size))
                    {
                        Certificates.Dispose();
                        localBuffer.Dispose();
                        throw new InvalidOperationException("Unable to read signer information.");
                    }
                    using (localBuffer)
                    {
                        var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(localBuffer.DangerousGetHandle());
                        var subjectId = new UniversalSubjectIdentifier(signerInfo.Issuer, signerInfo.SerialNumber);
                        var certs = GetCertificatesFromMessage(msgHandle);
                        if (subjectId.Type == SubjectIdentifierType.SubjectKeyIdentifier)
                        {
                            Certificate = FindCertificate((string)subjectId.Value, certs);
                        }
                        else if (subjectId.Type == SubjectIdentifierType.IssuerAndSerialNumber)
                        {
                            Certificate = FindCertificate((X509IssuerSerial)subjectId.Value, certs);
                        }
                        DigestAlgorithm = new Oid(signerInfo.HashAlgorithm.pszObjId);
                        HashEncryptionAlgorithm = new Oid(signerInfo.HashEncryptionAlgorithm.pszObjId);
                        SerialNumber = ReadBlob(signerInfo.SerialNumber);
                        UnsignedAttributes = ReadAttributes(signerInfo.UnauthAttrs);
                        SignedAttributes = ReadAttributes(signerInfo.AuthAttrs);
                    }
                }
                finally
                {
                    msgHandle.Dispose();
                    store.Dispose();
                }
            }
        }
    }

    internal class UniversalSubjectIdentifier
    {
        public SubjectIdentifierType Type { get; }
        public object Value { get; }

        public UniversalSubjectIdentifier(CRYPTOAPI_BLOB issuer, CRYPTOAPI_BLOB serialNumber)
        {
            var allZeroSerial = IsBlobAllZero(serialNumber);
            if (allZeroSerial)
            {
                var x500Name = LocalBufferSafeHandle.Zero;
                var flags = EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING;
                uint size = 0;
                if (Crypt32.CryptDecodeObjectEx(flags, (IntPtr)7, issuer.pbData, issuer.cbData, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out x500Name, ref size))
                {
                    using (x500Name)
                    {
                        var info = Marshal.PtrToStructure<CERT_NAME_INFO>(x500Name.DangerousGetHandle());
                        for (var i = 0L; i < info.cRDN; i++)
                        {
                            var rdn = Marshal.PtrToStructure<CERT_RDN>(new IntPtr(info.rgRDN.ToInt64() + i * Marshal.SizeOf<CERT_RDN>()));
                            for (var j = 0; j < rdn.cRDNAttr; j++)
                            {
                                var attribute = Marshal.PtrToStructure<CERT_RDN_ATTR>(new IntPtr(rdn.rgRDNAttr.ToInt64() + j * Marshal.SizeOf<CERT_RDN_ATTR>()));
                                if (attribute.pszObjId == KnownOids.KeyId)
                                {
                                    Type = SubjectIdentifierType.SubjectKeyIdentifier;
                                    var ski = new byte[attribute.Value.cbData];
                                    Marshal.Copy(attribute.Value.pbData, ski, 0, ski.Length);
                                    Value = HashHelpers.HexEncodeBigEndian(ski);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            unsafe
            {
                var result = Crypt32.CertNameToStr(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, new IntPtr(&issuer), CertNameStrType.CERT_X500_NAME_STR | CertNameStrType.CERT_NAME_STR_REVERSE_FLAG, null, 0);
                if (result <= 1)
                {
                    throw new InvalidOperationException();
                }
                var builder = new StringBuilder((int)result);
                var final = Crypt32.CertNameToStr(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, new IntPtr(&issuer), CertNameStrType.CERT_X500_NAME_STR | CertNameStrType.CERT_NAME_STR_REVERSE_FLAG, builder, result);
                if (final <= 1)
                {
                    throw new InvalidOperationException();
                }
                var serial = new byte[serialNumber.cbData];
                Marshal.Copy(serialNumber.pbData, serial, 0, serial.Length);
                var issuerSerial = new X509IssuerSerial();
                issuerSerial.IssuerName = builder.ToString();
                issuerSerial.SerialNumber = HashHelpers.HexEncodeBigEndian(serial);
                Value = issuerSerial;
                Type = SubjectIdentifierType.IssuerAndSerialNumber;
            }
        }

        private static bool IsBlobAllZero(CRYPTOAPI_BLOB blob)
        {
            unsafe
            {
                var data = (byte*)blob.pbData.ToPointer();
                for (var i = 0; i < blob.cbData; i++)
                {
                    if (data[i] != 0)
                    {
                        return false;
                    }
                }
                return true;
            }

        }
    }
}
