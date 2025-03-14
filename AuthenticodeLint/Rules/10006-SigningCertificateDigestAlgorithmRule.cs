using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class SigningCertificateDigestAlgorithmRule : CertificateChainRuleBase
    {
        public override int RuleId => 10006;

        public override string RuleName => "Strong Certificate Chain";

        public override string ShortDescription => "Checks the signing certificate's and chain's signature algorithm.";

        public override RuleSet RuleSet => RuleSet.All;

        protected override bool ValidateChain(ICmsSignature signer, X509Chain chain, SignatureLogger verboseWriter)
        {
            return ValidateStrongChain(signer, chain, verboseWriter);
        }

        private static bool ValidateStrongChain(ICmsSignature signature, X509Chain chain, SignatureLogger verboseWriter)
        {
            var signatureStrength = GetHashStrenghForComparison(signature.DigestAlgorithm!.Value!);
            var strongShaChain = true;
            var leafCertificateSignatureAlgorithm = chain.ChainElements[0].Certificate.SignatureAlgorithm;
            var leafCertificateSignatureAlgorithmStrength = GetHashStrenghForComparison(leafCertificateSignatureAlgorithm.Value!);
            //We use count-1 because we don't want to validate the root certificate.
            for (var i = 0; i < chain.ChainElements.Count - 1; i++)
            {
                var element = chain.ChainElements[i];
                var signatureAlgorithm = element.Certificate.SignatureAlgorithm;
                var certificateHashStrength = GetHashStrenghForComparison(signatureAlgorithm.Value!);
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
            return oid switch
            {
                KnownOids.MD2 => 2,
                KnownOids.MD4 => 4,
                KnownOids.MD5 => 5,
                KnownOids.SHA1 or KnownOids.sha1ECDSA or KnownOids.sha1RSA => 10,
                KnownOids.SHA256 or KnownOids.sha256ECDSA or KnownOids.sha256RSA => 256,
                KnownOids.SHA384 or KnownOids.sha384ECDSA or KnownOids.sha384RSA => 384,
                KnownOids.SHA512 or KnownOids.sha512ECDSA or KnownOids.sha512RSA => 512,
                _ => 0,
            };
        }
    }
}
