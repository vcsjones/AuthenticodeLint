using AuthenticodeLint.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint
{
    public interface ICounterSignature
    {
        Oid Oid { get; }
        Oid DigestAlgorithm { get; }
        Oid HashEncryptionAlgorithm { get; }
        CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        CryptographicAttributeObjectCollection SignedAttributes { get; }
    }
    public abstract class CounterSignatureBase : ICounterSignature
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
                for(var j = 0; j < structure.cValue; j++)
                {
                    var blob = Marshal.PtrToStructure<CRYPTOAPI_BLOB>(structure.rgValue + j * blobSize);
                    asnValues.Add(new AsnEncodedData(structure.pszObjId, ReadBlob(blob)));
                }
                collection.Add(new CryptographicAttributeObject(new Oid(structure.pszObjId), asnValues));
            }
            return collection;
        }
    }

    public class AuthenticodeSignature : CounterSignatureBase
    {

        public override Oid DigestAlgorithm { get; }
        public override Oid HashEncryptionAlgorithm { get; }
        public override CryptographicAttributeObjectCollection UnsignedAttributes { get; }
        public override CryptographicAttributeObjectCollection SignedAttributes { get; }
        public override byte[] SerialNumber { get; }

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
}
