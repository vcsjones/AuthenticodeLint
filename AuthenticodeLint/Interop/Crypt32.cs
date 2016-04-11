using System;
using System.Runtime.InteropServices;

namespace AuthenticodeLint.Interop
{
    internal static class Crypt32
    {
        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptQueryObject", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptQueryObject
        (
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryObjectType dwObjectType,
            [param: In, MarshalAs(UnmanagedType.LPWStr)] string pvObject,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryContentFlagType dwExpectedContentTypeFlags,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryFormatFlagType dwExpectedFormatTypeFlags,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptQueryObjectFlags dwFlags,
            [param: Out, MarshalAs(UnmanagedType.U4)] out EncodingType pdwMsgAndCertEncodingType,
            [param: Out, MarshalAs(UnmanagedType.U4)] out CryptQueryContentType pdwContentType,
            [param: Out, MarshalAs(UnmanagedType.U4)] out CryptQueryFormatType pdwFormatType,
            [param: Out] out CertStoreSafeHandle phCertStore,
            [param: Out] out CryptMsgSafeHandle phMsg,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr ppvContext
         );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptMsgClose", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptMsgClose([param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr hCryptMsg);

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CertCloseStore", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertCloseStore
        (
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr hCertStore,
            [param: In, MarshalAs(UnmanagedType.U4)] uint dwFlags
        );

        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptMsgGetParam", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe extern bool CryptMsgGetParam
        (
            [param: In] CryptMsgSafeHandle hCryptMsg,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptMsgParamType dwParamType,
            [param: In, MarshalAs(UnmanagedType.U4)] uint dwIndex,
            [param: In] void* pvData,
            [param: In, Out, MarshalAs(UnmanagedType.U4)] ref uint pcbData
        );
    }

    internal enum CryptQueryObjectType : uint
    {
        CERT_QUERY_OBJECT_FILE = 0x00000001,
        CERT_QUERY_OBJECT_BLOB = 0x00000002
    }

    internal enum CryptMsgParamType : uint
    {
        CMSG_TYPE_PARAM = 1,
        CMSG_CONTENT_PARAM = 2,
        CMSG_BARE_CONTENT_PARAM = 3,
        CMSG_INNER_CONTENT_TYPE_PARAM = 4,
        CMSG_SIGNER_COUNT_PARAM = 5,
        CMSG_SIGNER_INFO_PARAM = 6,
        CMSG_SIGNER_CERT_INFO_PARAM = 7,
        CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8,
        CMSG_SIGNER_AUTH_ATTR_PARAM = 9,
        CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10,
        CMSG_CERT_COUNT_PARAM = 11,
        CMSG_CERT_PARAM = 12,
        CMSG_CRL_COUNT_PARAM = 13,
        CMSG_CRL_PARAM = 14,
        CMSG_ENVELOPE_ALGORITHM_PARAM = 15,
        CMSG_RECIPIENT_COUNT_PARAM = 17,
        CMSG_RECIPIENT_INDEX_PARAM = 18,
        CMSG_RECIPIENT_INFO_PARAM = 19,
        CMSG_HASH_ALGORITHM_PARAM = 20,
        CMSG_HASH_DATA_PARAM = 21,
        CMSG_COMPUTED_HASH_PARAM = 22,
        CMSG_ENCRYPT_PARAM = 26,
        CMSG_ENCRYPTED_DIGEST = 27,
        CMSG_ENCODED_SIGNER = 28,
        CMSG_ENCODED_MESSAGE = 29,
        CMSG_VERSION_PARAM = 30,
        CMSG_ATTR_CERT_COUNT_PARAM = 31,
        CMSG_ATTR_CERT_PARAM = 32,
        CMSG_CMS_RECIPIENT_COUNT_PARAM = 33,
        CMSG_CMS_RECIPIENT_INDEX_PARAM = 34,
        CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35,
        CMSG_CMS_RECIPIENT_INFO_PARAM = 36,
        CMSG_UNPROTECTED_ATTR_PARAM = 37,
        CMSG_SIGNER_CERT_ID_PARAM = 38,
        CMSG_CMS_SIGNER_INFO_PARAM = 39,
    }

    [type: Flags]
    internal enum CryptQueryContentFlagType : uint
    {
        CERT_QUERY_CONTENT_FLAG_CERT = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CERT,
        CERT_QUERY_CONTENT_FLAG_CTL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CTL,
        CERT_QUERY_CONTENT_FLAG_CRL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CRL,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_STORE,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CERT,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CTL,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CRL,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED,
        CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS7_UNSIGNED,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED,
        CERT_QUERY_CONTENT_FLAG_PKCS10 = 1u <<(int)CryptQueryContentType.CERT_QUERY_CONTENT_PKCS10,
        CERT_QUERY_CONTENT_FLAG_PFX = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PFX,
        CERT_QUERY_CONTENT_FLAG_CERT_PAIR = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_CERT_PAIR,
        CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD = 1u << (int)CryptQueryContentType.CERT_QUERY_CONTENT_PFX_AND_LOAD,
        CERT_QUERY_CONTENT_FLAG_ALL =
            CERT_QUERY_CONTENT_FLAG_CERT |
            CERT_QUERY_CONTENT_FLAG_CTL |
            CERT_QUERY_CONTENT_FLAG_CRL |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
            CERT_QUERY_CONTENT_FLAG_PKCS10 |
            CERT_QUERY_CONTENT_FLAG_PFX |
            CERT_QUERY_CONTENT_FLAG_CERT_PAIR, //wincrypt.h purposefully omits CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD
        CERT_QUERY_CONTENT_FLAG_ALL_ISSUER_CERT =
            CERT_QUERY_CONTENT_FLAG_CERT |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE |
            CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED
    }

    internal enum CryptQueryContentType : uint
    {
        CERT_QUERY_CONTENT_CERT = 1,
        CERT_QUERY_CONTENT_CTL = 2,
        CERT_QUERY_CONTENT_CRL = 3,
        CERT_QUERY_CONTENT_SERIALIZED_STORE = 4,
        CERT_QUERY_CONTENT_SERIALIZED_CERT = 5,
        CERT_QUERY_CONTENT_SERIALIZED_CTL = 6,
        CERT_QUERY_CONTENT_SERIALIZED_CRL = 7,
        CERT_QUERY_CONTENT_PKCS7_SIGNED = 8,
        CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9,
        CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10,
        CERT_QUERY_CONTENT_PKCS10 = 11,
        CERT_QUERY_CONTENT_PFX = 12,
        CERT_QUERY_CONTENT_CERT_PAIR = 13,
        CERT_QUERY_CONTENT_PFX_AND_LOAD = 14
    }

    internal enum CryptQueryFormatType : uint
    {
        CERT_QUERY_FORMAT_BINARY = 1,
        CERT_QUERY_FORMAT_BASE64_ENCODED = 2,
        CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3
    }

    [type: Flags]
    internal enum CryptQueryFormatFlagType : uint
    {
        CERT_QUERY_FORMAT_FLAG_BINARY = 1u << (int)CryptQueryFormatType.CERT_QUERY_FORMAT_BINARY,
        CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = 1u << (int)CryptQueryFormatType.CERT_QUERY_FORMAT_BASE64_ENCODED,
        CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = 1u << (int)CryptQueryFormatType.CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED,
        CERT_QUERY_FORMAT_FLAG_ALL = 
            CERT_QUERY_FORMAT_FLAG_BINARY |
            CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED |
            CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED
    }

    [type: Flags]
    internal enum CryptQueryObjectFlags : uint
    {
        NONE = 0
    }

    internal enum EncodingType : uint
    {
        PKCS_7_ASN_ENCODING = 0x10000,
        X509_ASN_ENCODING = 0x1
    }
}
