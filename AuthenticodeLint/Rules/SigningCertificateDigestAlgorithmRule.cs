using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint.Rules
{
    public class SigningCertificateDigestAlgorithmRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10006;

        public string RuleName { get; } = "SHA2 Certificate Chain";

        public string ShortDescription { get; } = "Checks the signing certificate's and chain's signature algorithm.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLoggerBase verboseWriter)
        {
            var signatures = graph.VisitAll();
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                var certificates = signature.AdditionalCertificates;
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.ExtraStore.AddRange(certificates);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    bool success = chain.Build(signature.SignerInfo.Certificate);
                    if (!success)
                    {
                        verboseWriter.LogSignatureMessage(signature.SignerInfo, $"Cannot build a chain successfully with signing certificate {signature.SignerInfo.Certificate.SerialNumber}.");
                        result = RuleResult.Fail;
                        continue;
                    }
                    var chainResult = ValidateSha2Chain(signature.SignerInfo, chain, verboseWriter);
                    if (!chainResult)
                    {
                        result = RuleResult.Fail;
                    }
                }
            }
            return result;
        }

        private static bool ValidateSha2Chain(SignerInfo signatureInfo, X509Chain chain, SignatureLoggerBase verboseWriter)
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
