using AuthenticodeLint.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AuthenticodeLint.Rules
{
    public class NoUnknownCertificatesRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10010;

        public string RuleName { get; } = "No Unknown Certificates";

        public string ShortDescription { get; } = "Checks for unknown embedded certificates.";

        public RuleResult Validate(IReadOnlyList<ISignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var result = RuleResult.Pass;
            //We exclude Authenticode timestamps because they cannot contain "additional" certificates but rather
            //Use their parent. Including Authenticode timestamps will produce duplicate warnings.
            var signatures = graph.VisitAll(SignatureKind.AnySignature | SignatureKind.Rfc3161Signature);
            foreach (var signature in signatures)
            {
                var allEmbeddedCertificates = signature.AdditionalCertificates.Cast<X509Certificate2>().ToList();
                var certificatesRequiringEliminiation = new HashSet<X509Certificate2>(allEmbeddedCertificates, new CertificateThumbprintComparer());
                foreach (var certificate in allEmbeddedCertificates)
                {
                    if (!certificatesRequiringEliminiation.Contains(certificate))
                    {
                        //This certificate was already eliminated because it was part of a previous chain.
                        continue;
                    }
                    using (var chain = new X509Chain())
                    {
                        chain.ChainPolicy.ExtraStore.AddRange(signature.AdditionalCertificates);
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                        //All we care is that we can even find an authority.
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags & ~X509VerificationFlags.AllowUnknownCertificateAuthority;
                        if (chain.Build(certificate))
                        {
                            certificatesRequiringEliminiation.ExceptWith(chain.ChainElements.Cast<X509ChainElement>().Select(c => c.Certificate));
                        }
                    }
                }
                if (certificatesRequiringEliminiation.Count > 0)
                {
                    foreach (var certificate in certificatesRequiringEliminiation)
                    {
                        verboseWriter.LogSignatureMessage(signature, $"Signature contained untrusted certificate \"{certificate.Subject}\" ({certificate.Thumbprint}).");
                    }
                    result = RuleResult.Fail;
                }
            }
            return result;
        }



        private class CertificateThumbprintComparer : IEqualityComparer<X509Certificate2>
        {
            public bool Equals(X509Certificate2 x, X509Certificate2 y)
            {
                return x.Thumbprint == y.Thumbprint;
            }

            public int GetHashCode(X509Certificate2 obj)
            {
                return obj.Thumbprint.GetHashCode();
            }
        }
    }
}
