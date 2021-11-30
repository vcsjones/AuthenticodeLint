using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint
{
    public static class BitStrengthCalculator
    {
        private static readonly ConcurrentDictionary<string, int> _cachedEccCurveSizes = new ConcurrentDictionary<string, int>();

        public static CertificateBitStrength CalculateStrength(X509Certificate2 certificate)
        {
            PublicKeyAlgorithm keyAlgorithm;
            int? bitSize;
            switch (certificate.PublicKey.Oid.Value)
            {
                case KnownOids.X509Algorithms.Ecc:
                    keyAlgorithm = PublicKeyAlgorithm.ECDSA;
                    string? parameterOid = OidParser.ReadFromBytes(certificate.PublicKey.EncodedParameters.RawData);

                    if (parameterOid is null)
                    {
                        bitSize = null;
                    }
                    else
                    {
                        bitSize = _cachedEccCurveSizes.GetOrAdd(parameterOid, static oid =>
                        {
                            var curve = ECCurve.CreateFromValue(oid);
                            using (var ecdsa = ECDsa.Create(curve))
                            {
                                return ecdsa.KeySize;
                            }
                        });
                    }
                    break;
                case KnownOids.X509Algorithms.RSA:
                    keyAlgorithm = PublicKeyAlgorithm.RSA;
                    using (RSA? rsa = certificate.GetRSAPublicKey())
                    {
                        bitSize = rsa?.KeySize;
                    }
                    break;
                default:
                    keyAlgorithm = PublicKeyAlgorithm.Other;
                    bitSize = null;
                    break;
            }
            return new CertificateBitStrength(keyAlgorithm, bitSize);
        }
    }

    public class CertificateBitStrength
    {
        public CertificateBitStrength(PublicKeyAlgorithm algorithmName, int? bitSize)
        {
            AlgorithmName = algorithmName;
            BitSize = bitSize;
        }

        public PublicKeyAlgorithm AlgorithmName { get; }
        public int? BitSize { get; }
    }

    public enum PublicKeyAlgorithm
    {
        Other = 0,
        RSA = 1,
        DSA = 2,
        ECDSA = 3
    }
}
