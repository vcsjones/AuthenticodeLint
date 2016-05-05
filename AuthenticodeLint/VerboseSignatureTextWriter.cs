using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class MemorySignatureLogger : SignatureLogger
    {
        public override void LogMessage(string message) => Messages.Add(message);

        public override void LogSignatureMessage(SignerInfo signature, string message)
        {
            var digestString = HashHelpers.GetHashForSignature(signature);
            Messages.Add($"Signature {digestString}: {message}");
        }
    }

    public class NullSignatureLogger : SignatureLogger
    {
        public override void LogMessage(string message)
        {
        }

        public override void LogSignatureMessage(SignerInfo signature, string message)
        {
        }
    }

    public abstract class SignatureLogger
    {
        public static SignatureLogger Null { get; } = new NullSignatureLogger();

        public List<string> Messages { get; } = new List<string>();

        public abstract void LogSignatureMessage(SignerInfo signature, string message);
        public abstract void LogMessage(string message);
    }
}
