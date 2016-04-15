using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint.Rules
{
    public class SigningCertificateDigestAlgorithmRule : CertificateChainRuleBase
    {
        public override int RuleId { get; } = 10006;

        public override string RuleName { get; } = "SHA2 Certificate Chain";

        public override string ShortDescription { get; } = "Checks the signing certificate's and chain's signature algorithm.";

        protected override bool ValidateChain(Signature signer, X509Chain chain, SignatureLogger verboseWriter)
        {
            return ValidateSha2Chain(signer.SignerInfo, chain, verboseWriter);
        }

        private static bool ValidateSha2Chain(SignerInfo signatureInfo, X509Chain chain, SignatureLogger verboseWriter)
        {
            var strongSha2Chain = true;
            //We use count-1 because we don't want to validate SHA2 on the root certificate.
            for(var i = 0; i < chain.ChainElements.Count-1; i++)
            {
                var element = chain.ChainElements[i];
                var signatureAlgorithm = element.Certificate.SignatureAlgorithm;
                switch (signatureAlgorithm.Value)
                {
                    case KnownOids.sha256ECDSA:
                    case KnownOids.sha384ECDSA:
                    case KnownOids.sha512ECDSA:
                    case KnownOids.sha256RSA:
                    case KnownOids.sha384RSA:
                    case KnownOids.sha512RSA:
                        continue;
                    default:
                        verboseWriter.LogSignatureMessage(signatureInfo, $"Certificate {element.Certificate.Thumbprint} in chain uses {element.Certificate.SignatureAlgorithm.FriendlyName} for its signature algorithm instead of SHA2.");
                        strongSha2Chain = false;
                        break;
                }
            }
            return strongSha2Chain;
        }
    }
}
