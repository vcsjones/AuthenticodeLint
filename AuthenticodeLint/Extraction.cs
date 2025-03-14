using AuthenticodeExaminer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AuthenticodeLint
{
    public class Extraction
    {
        public static void ExtractToDisk(string file, CheckConfiguration configuration, IReadOnlyList<ICmsSignature> signatureGraph)
        {
            var fileDirectory = Path.Combine(configuration.ExtractPath!, Path.GetFileName(file));
            if (Directory.Exists(fileDirectory))
            {
                Directory.Delete(fileDirectory, true);
            }
            Directory.CreateDirectory(fileDirectory);
            var signatures = signatureGraph.VisitAll(SignatureKind.AnySignature);
            foreach(var signature in signatures)
            {
                var signatureHash = HashHelpers.GetHashForSignature(signature);
                var signatureDirectory = Path.Combine(fileDirectory, signatureHash);
                var certificateDirectory = Path.Combine(signatureDirectory, "Certificates");
                if (!Directory.Exists(certificateDirectory))
                {
                    Directory.CreateDirectory(certificateDirectory);
                }
                foreach(var certificate in signature.AdditionalCertificates)
                {
                    var thumbprint = certificate.Thumbprint;
                    var serialized = SerializeCertificate(certificate);
                    if (serialized != null)
                    {
                        File.WriteAllText(Path.Combine(certificateDirectory, thumbprint + ".cer"), serialized);
                    }
                }
            }
        }

        private static string SerializeCertificate(X509Certificate2 certificate)
        {
            var octets = certificate.Export(X509ContentType.Cert);
            var formatted = Convert.ToBase64String(octets);
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            var i = 0;
            while (i < formatted.Length)
            {
                const int MAX_LINE_SIZE = 64;
                var size = Math.Min(MAX_LINE_SIZE, formatted.Length - i);
                builder.AppendLine(formatted.Substring(i, size));
                i += size;
            }
            builder.AppendLine("-----END CERTIFICATE-----");
            return builder.ToString();
        }
    }
}
