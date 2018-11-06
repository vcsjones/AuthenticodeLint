using System;
using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLint.Rules
{
    public class PublisherInformationUrlHttpsRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10005;

        public string RuleName { get; } = "Publisher Information URL HTTPS Rule";

        public string ShortDescription { get; } = "Checks that the signature uses HTTPS for the publisher's URL.";

        public RuleSet RuleSet { get; } = RuleSet.All;

        public RuleResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
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
                if (info == null || info.IsEmpty)
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogSignatureMessage(signature, "Signature does not have any publisher information.");
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(info.UrlLink))
                    {
                        result = RuleResult.Fail;
                        verboseWriter.LogSignatureMessage(signature, "Signature does not have an accompanying URL.");
                    }
                    else if (!info.UrlLink.StartsWith(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                    {
                        result = RuleResult.Fail;
                        verboseWriter.LogSignatureMessage(signature, $"Signature's publisher information URL \"{info.UrlLink}\" does not use the secure HTTPS scheme.");
                    }
                }
            }
            return result;
        }
    }
}
