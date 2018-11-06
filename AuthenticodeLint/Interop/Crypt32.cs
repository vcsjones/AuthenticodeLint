using System.Runtime.InteropServices;
using System.Text;

namespace AuthenticodeLint.Interop
{
    internal static class Crypt32
    {
        [method: DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, EntryPoint = "CryptBinaryToString", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe extern bool CryptBinaryToString
        (
            [param: In] byte[] pbBinary,
            [param: In, MarshalAs(UnmanagedType.U4)] uint cbBinary,
            [param: In, MarshalAs(UnmanagedType.U4)] CryptBinaryToStringFlags dwFlags,
            [param: In, Out] StringBuilder pszString,
            [param: In, Out] ref uint pcchString
        );
    }

    internal enum CryptBinaryToStringFlags : uint
    {
        CRYPT_STRING_BASE64HEADER = 0x00000000,
        CRYPT_STRING_BASE64 = 0x00000001,
        CRYPT_STRING_BINARY = 0x00000002,
        CRYPT_STRING_BASE64REQUESTHEADER = 0x00000003,
        CRYPT_STRING_HEX = 0x00000004,
        CRYPT_STRING_HEXASCII = 0x00000005,
        CRYPT_STRING_BASE64X509CRLHEADER = 0x00000009,
        CRYPT_STRING_HEXADDR = 0x0000000a,
        CRYPT_STRING_HEXASCIIADDR = 0x0000000b,
        CRYPT_STRING_HEXRAW = 0x0000000c,
        CRYPT_STRING_STRICT = 0x20000000,

        CRYPT_STRING_NOCRLF = 0x40000000,
        CRYPT_STRING_NOCR = 0x80000000,

    }
}
