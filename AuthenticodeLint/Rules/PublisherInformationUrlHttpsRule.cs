using System;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class PublisherInformationUrlHttpsRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10005;

        public string RuleName { get; } = "Publisher Information URL HTTPS Rule";

        public string ShortDescription { get; } = "Checks that the signature uses HTTPS for the publisher's URL.";

        public RuleResult Validate(Graph<SignerInfo> graph, SignatureLoggerBase verboseWriter)
        {
            var signatures = graph.VisitAll();
            var result = RuleResult.Pass;
            foreach(var signature in signatures)
            {
                PublisherInformation info = null;
                foreach(var attribute in signature.SignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.OpusInfo)
                    {
                        info = new PublisherInformation(attribute.Values[0]);
                        break;
                    }
                }
                if (info == null)
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogMessage(signature, "Signature does not have any publisher information.");
                }
                if (string.IsNullOrWhiteSpace(info.UrlLink))
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogMessage(signature, "Signature does not have an accompanying URL.");
                }
                if (!info.UrlLink.StartsWith(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogMessage(signature, $"Signature's publisher information URL \"{info.UrlLink}\" does not use the secure HTTPS scheme.");
                }
            }
            return result;
        }
    }
}
