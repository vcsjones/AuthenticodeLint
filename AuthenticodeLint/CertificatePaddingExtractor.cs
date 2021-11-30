using AuthenticodeLint.PE;
using System;
using System.IO;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint
{
    public static class CertificatePaddingExtractor
    {
        public static byte[]? ExtractPadding(string filePath)
        {
            using (var file = new PortableExecutable(filePath))
            {
                var dosHeader = file.GetDosHeader();
                var peHeader = file.GetPEHeader(dosHeader);
                var signatureLocation = peHeader.DataDirectories[ImageDataDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY];
                using (var signatureData = file.ReadDataDirectory(signatureLocation))
                {
                    using (var reader = new BinaryReader(signatureData))
                    {
                        var winCertLength = reader.ReadUInt32();
                        var winCertRevision = reader.ReadUInt16();
                        var winCertType = reader.ReadUInt16();
                        if (winCertRevision != 0x200 && winCertRevision != 0x100)
                        {
                            return null;
                        }
                        if (winCertType != 0x0002)
                        {
                            return null;
                        }
                        using (var memoryStream = new MemoryStream())
                        {
                            int read;
                            Span<byte> buffer = stackalloc byte[0x400];
                            while ((read = reader.Read(buffer)) > 0)
                            {
                                memoryStream.Write(buffer.Slice(0, read));
                            }
                            var winCertificate = memoryStream.ToArray();
                            var signer = new SignedCms();
                            signer.Decode(winCertificate);
                            var roundTrip = signer.Encode();
                            var sizeDifference = winCertificate.Length - roundTrip.Length;
                            var difference = new byte[sizeDifference];
                            Buffer.BlockCopy(winCertificate, roundTrip.Length, difference, 0, difference.Length);
                            return difference;
                        }
                    }
                }
            }
        }
    }
}
