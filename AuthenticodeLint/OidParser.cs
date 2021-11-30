using System.Formats.Asn1;

namespace AuthenticodeLint
{
    public static class OidParser
    {
        public static string? ReadFromBytes(byte[] data)
        {
            try
            {
                AsnReader reader = new AsnReader(data, AsnEncodingRules.DER);
                return reader.ReadObjectIdentifier();
            }
            catch (AsnContentException)
            {
                return null;
            }
        }
    }
}
