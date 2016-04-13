using AuthenticodeLint.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint
{
    public abstract class SignatureBase : IDisposable
    {
        internal CMSG_SIGNER_INFO _signerInfo;

        protected SignatureBase(AsnEncodedData data)
        {

        }

        public Oid DigestAlgorithm => new Oid(_signerInfo.HashAlgorithm.pszObjId);
        public Oid HashEncryptionAlgorithm => new Oid(_signerInfo.HashEncryptionAlgorithm.pszObjId);

        public byte[] SerialNumber
        {
            get
            {
                var buffer = new byte[_signerInfo.SerialNumber.cbData];
                Marshal.Copy(_signerInfo.SerialNumber.pbData, buffer, 0, buffer.Length);
                return buffer;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public virtual void Dispose(bool disposing)
        {
        }

        ~SignatureBase()
        {
            Dispose(false);
        }
    }

    public class AuthenticodeSignature : SignatureBase
    {
        public unsafe AuthenticodeSignature(AsnEncodedData data) : base(data)
        {
            fixed (byte* dataPtr = data.RawData)
            {
                LocalBufferSafeHandle ptr;
                uint size = 0;
                if (Crypt32.CryptDecodeObjectEx(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, (IntPtr)500, new IntPtr(dataPtr), (uint)data.RawData.Length, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out ptr, ref size))
                {
                    using (ptr)
                    {
                        _signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(ptr.DangerousGetHandle());
                    }
                }
                else
                {
                    throw new InvalidOperationException("Failed to read authenticode signature");
                }
            }
        }
    }

    public class Rfc3161Signature : SignatureBase
    {
        private readonly X509Store _certificates;
        private readonly CryptMsgSafeHandle _messageHandle;

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
                    _certificates = new X509Store(store.DangerousGetHandle());
                    _messageHandle = msgHandle;
                    var size = 0u;
                    if (!Crypt32.CryptMsgGetParam(_messageHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, LocalBufferSafeHandle.Zero, ref size))
                    {
                        _messageHandle.Dispose();
                        throw new InvalidOperationException("Unable to read signer information.");
                    }
                    using (var localBuffer = LocalBufferSafeHandle.Alloc(size))
                    {
                        if (!Crypt32.CryptMsgGetParam(_messageHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, localBuffer, ref size))
                        {
                            _messageHandle.Dispose();
                            throw new InvalidOperationException("Unable to read signer information.");
                        }
                        _signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(localBuffer.DangerousGetHandle());
                    }
                }
                finally
                {
                    store.Dispose();
                }
            }
        }


        public override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _messageHandle.Dispose();
                _certificates.Dispose();
            }
        }
    }
}
