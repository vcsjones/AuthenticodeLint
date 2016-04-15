using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using AuthenticodeLint.Interop;
using System.Security.Cryptography.Pkcs;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class SignatureExtractor
    {
        public Graph<Signature> Extract(string filePath)
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
                switch(unchecked((uint)resultCode))
                {
                    case 0x80092009: //Cannot find request object. There's no signature.
                        return Graph<Signature>.Empty;
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

        private unsafe Graph<Signature> GetSignatures(CryptMsgSafeHandle messageHandle)
        {
            uint size = 0;
            var signatures = new List<SignerInfo>();
            if (Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_ENCODED_MESSAGE, 0, (void*)null, ref size))
            {
                var buffer = new byte[(int)size];
                fixed(byte* buf = buffer)
                {
                    if (Crypt32.CryptMsgGetParam(messageHandle, CryptMsgParamType.CMSG_ENCODED_MESSAGE, 0, buf, ref size))
                    {
                        return RecursiveSigner(new List<byte[]> { buffer });
                    }
                }
            }
            return null;
        }


        public static Graph<Signature> RecursiveSigner(IList<byte[]> cmsData)
        {
            var graphItems = new List<GraphItem<Signature>>();
            foreach (var data in cmsData)
            {
                var cms = new SignedCms();
                cms.Decode(data);
                foreach (var signer in cms.SignerInfos)
                {
                    var childCms = new List<byte[]>();
                    foreach (var attribute in signer.UnsignedAttributes)
                    {
                        if (attribute.Oid.Value == KnownOids.NestedSignatureOid)
                        {
                            foreach (var value in attribute.Values)
                            {
                                childCms.Add(value.RawData);
                            }
                        }
                    }
                    graphItems.Add(new GraphItem<Signature>(new Signature(signer, cms.Certificates), RecursiveSigner(childCms)));
                }
            }
            return new Graph<Signature>(graphItems);
        }
    }
}
