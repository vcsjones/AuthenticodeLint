using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public class VerboseSignatureLogger : SignatureLoggerBase
    {
        public override void LogMessage(string message) => Messages.Add(message);

        public override void LogSignatureMessage(SignerInfo signature, string message)
        {
            var digest = signature.SignatureDigest();
            var digestString = digest.Aggregate(new StringBuilder(), (acc, b) => acc.AppendFormat("{0:x2}", b)).ToString();
            Messages.Add($"Signature {digestString}: {message}");
        }
    }

    public class NullSignatureLogger : SignatureLoggerBase
    {
        public override void LogMessage(string message)
        {
        }

        public override void LogSignatureMessage(SignerInfo signature, string message)
        {
        }
    }

    public abstract class SignatureLoggerBase
    {
        public static SignatureLoggerBase Null { get; } = new NullSignatureLogger();

        internal List<string> Messages { get; } = new List<string>();

        public abstract void LogSignatureMessage(SignerInfo signature, string message);
        public abstract void LogMessage(string message);
    }
}
