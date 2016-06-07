using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using AuthenticodeLint.Interop;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class SignatureExtractor
    {
        public IReadOnlyList<ISignature> Extract(string filePath)
        {
            EncodingType encodingType;
            CryptQueryContentType contentType;
            CryptQueryFormatType formatType;
            CertStoreSafeHandle certStoreHandle = CertStoreSafeHandle.InvalidHandle;
            CryptMsgSafeHandle message = CryptMsgSafeHandle.InvalidHandle;
            var result = Crypt32.CryptQueryObject(CryptQueryObjectType.CERT_QUERY_OBJECT_FILE, filePath, CryptQueryContentFlagType.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CryptQueryFormatFlagType.CERT_QUERY_FORMAT_FLAG_BINARY, CryptQueryObjectFlags.NONE, out encodingType, out contentType, out formatType, out certStoreHandle, out message, IntPtr.Zero);
            if (!result)
            {
                var resultCode = Marshal.GetLastWin32Error();
                switch (unchecked((uint)resultCode))
                {
                    case 0x80092009: //Cannot find request object. There's no signature.
                        return new List<ISignature>().AsReadOnly();
                    default:
                        throw new Win32Exception(resultCode, "Failed to extract signature.");
                }
            }
            using (message)
            using (certStoreHandle) //The ctor of X509Store duplicates the store handle, so we need to clean up the one created here.
            {
                if (message.IsInvalid || message.IsClosed || certStoreHandle.IsClosed || certStoreHandle.IsInvalid)
                {
                    return null;
                }
                return GetSignatures(message);
            }
        }

        private unsafe IReadOnlyList<ISignature> GetSignatures(CryptMsgSafeHandle messageHandle)
        {
            var countSize = 0u;
            if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, LocalBufferSafeHandle.Zero, ref countSize))
            {
                return null;
            }
            uint signerCount;
            using (var countHandle = LocalBufferSafeHandle.Alloc(countSize))
            {
                if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, countHandle, ref countSize))
                {
                    return null;
                }
                signerCount = (uint)Marshal.ReadInt32(countHandle.DangerousGetHandle());
            }
            var signatures = new List<ISignature>();
            for (var i = 0u; i < signerCount; i++)
            {
                var signerSize = 0u;
                if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, i, LocalBufferSafeHandle.Zero, ref signerSize))
                {
                    continue;
                }
                using (var signerHandle = LocalBufferSafeHandle.Alloc(signerSize))
                {
                    if (!Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, i, signerHandle, ref signerSize))
                    {
                        continue;
                    }
                    var signature = new Signature(SignatureKind.Signature, messageHandle, signerHandle);
                    signatures.Add(signature);
                }
            }
            return signatures.AsReadOnly();
        }
    }
}
