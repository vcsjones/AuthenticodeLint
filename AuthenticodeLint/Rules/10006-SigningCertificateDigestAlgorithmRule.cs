using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class SigningCertificateDigestAlgorithmRule : CertificateChainRuleBase
    {
        public override int RuleId { get; } = 10006;

        public override string RuleName { get; } = "Strong Certificate Chain";

        public override string ShortDescription { get; } = "Checks the signing certificate's and chain's signature algorithm.";

        public override RuleSet RuleSet { get; } = RuleSet.All;
        
        protected override bool ValidateChain(ICmsSignature signer, X509Chain chain, SignatureLogger verboseWriter)
        {
            return ValidateStrongChain(signer, chain, verboseWriter);
        }

        private static bool ValidateStrongChain(ICmsSignature signature, X509Chain chain, SignatureLogger verboseWriter)
        {
            var signatureStrength = GetHashStrenghForComparison(signature.DigestAlgorithm.Value);
            var strongShaChain = true;
            var leafCertificateSignatureAlgorithm = chain.ChainElements[0].Certificate.SignatureAlgorithm;
            var leafCertificateSignatureAlgorithmStrength = GetHashStrenghForComparison(leafCertificateSignatureAlgorithm.Value);
            //We use count-1 because we don't want to validate the root certificate.
            for (var i = 0; i < chain.ChainElements.Count - 1; i++)
            {
                var element = chain.ChainElements[i];
                var signatureAlgorithm = element.Certificate.SignatureAlgorithm;
                var certificateHashStrength = GetHashStrenghForComparison(signatureAlgorithm.Value);
                if (certificateHashStrength < signatureStrength)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Certificate {element.Certificate.Thumbprint} in chain uses {element.Certificate.SignatureAlgorithm.FriendlyName} for its signature algorithm instead of at least {signature.DigestAlgorithm.FriendlyName}.");
                    strongShaChain = false;
                }
                //Check that all intermediates are at least as strong as the leaf.
                else if (certificateHashStrength < leafCertificateSignatureAlgorithmStrength)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Certificate {element.Certificate.Thumbprint} in chain uses {element.Certificate.SignatureAlgorithm.FriendlyName} for its signature algorithm instead of at least {signature.DigestAlgorithm.FriendlyName}.");
                }
            }
            return strongShaChain;
        }

        //Returns a value for comparison. These values are not intended to be a bit size, but only used for comparing
        //angainst other values.
        private static int GetHashStrenghForComparison(string oid)
        {
            switch (oid)
            {
                case KnownOids.MD2:
                    return 2;
                case KnownOids.MD4:
                    return 4;
                case KnownOids.MD5:
                    return 5;
                case KnownOids.SHA1:
                case KnownOids.sha1ECDSA:
                case KnownOids.sha1RSA:
                    return 10;
                case KnownOids.SHA256:
                case KnownOids.sha256ECDSA:
                case KnownOids.sha256RSA:
                    return 256;
                case KnownOids.SHA384:
                case KnownOids.sha384ECDSA:
                case KnownOids.sha384RSA:
                    return 384;
                case KnownOids.SHA512:
                case KnownOids.sha512ECDSA:
                case KnownOids.sha512RSA:
                    return 512;
                default:
                    return 0;
            }
        }
    }
}
