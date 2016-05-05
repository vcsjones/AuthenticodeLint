using AuthenticodeLint.Interop;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AuthenticodeLint
{
    public class Extraction
    {
        public static void ExtractToDisk(string file, CheckConfiguration configuration, Graph<Signature> signatureGraph)
        {
            var fileDirectory = Path.Combine(configuration.ExtractPath, Path.GetFileName(file));
            if (Directory.Exists(fileDirectory))
            {
                Directory.Delete(fileDirectory, true);
            }
            Directory.CreateDirectory(fileDirectory);
            var signatures = signatureGraph.VisitAll();
            foreach(var signature in signatures)
            {
                var signatureHash = HashHelpers.GetHashForSignature(signature.SignerInfo);
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
            string base64Certificate = null;
            var binaryCertificate = certificate.Export(X509ContentType.Cert);

            uint size = 0;
            if (Crypt32.CryptBinaryToString(binaryCertificate, (uint)binaryCertificate.Length, CryptBinaryToStringFlags.CRYPT_STRING_BASE64HEADER, null, ref size))
            {
                var builder = new StringBuilder((int)size);
                if (Crypt32.CryptBinaryToString(binaryCertificate, (uint)binaryCertificate.Length, CryptBinaryToStringFlags.CRYPT_STRING_BASE64HEADER, builder, ref size))
                {
                    base64Certificate = builder.ToString();
                }
            }
            return base64Certificate; 
        }
    }
}
