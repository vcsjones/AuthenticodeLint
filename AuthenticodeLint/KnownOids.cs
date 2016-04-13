namespace AuthenticodeLint
{
    internal static class KnownOids
    {
        public static string SHA1 { get; } = "1.3.14.3.2.26";
        public static string SHA256 { get; } = "2.16.840.1.101.3.4.2.1";
        public static string SHA384 { get; } = "2.16.840.1.101.3.4.2.2";
        public static string SHA512 { get; } = "2.16.840.1.101.3.4.2.3";
        public static string MD5 { get; } = "1.2.840.113549.2.5";
        public static string MD4 { get; } = "1.2.840.113549.2.4";
        public static string MD2 { get; } = "1.2.840.113549.2.2";


        public static string Rfc3161CounterSignature { get; } = "1.3.6.1.4.1.311.3.3.1";
        public static string AuthenticodeCounterSignature { get; } = "1.2.840.113549.1.9.6";
        public static string MessageDigest { get; } = "1.2.840.113549.1.9.4";
    }
}
