using System;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint.Rules
{
    public class PublisherInformationPresentRule : IAuthenticodeRule
    {
        public int RuleId { get; } = 10004;

        public string RuleName { get; } = "Publisher Information Rule";

        public string ShortDescription { get; } = "Checks that the signature provided publisher information.";

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
                if (string.IsNullOrWhiteSpace(info.Description))
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogMessage(signature, "Signature does not have an accompanying description.");
                }

                if (string.IsNullOrWhiteSpace(info.UrlLink))
                {
                    result = RuleResult.Fail;
                    verboseWriter.LogMessage(signature, "Signature does not have an accompanying URL.");
                }
            }
            return result;
        }
    }
}
