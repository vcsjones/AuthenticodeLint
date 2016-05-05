using System;

namespace AuthenticodeLint.Rules
{
    public class PublisherInformationPresentRule : IAuthenticodeSignatureRule
    {
        public int RuleId { get; } = 10004;

        public string RuleName { get; } = "Publisher Information Present";

        public string ShortDescription { get; } = "Checks that the signature provided publisher information.";

        public RuleResult Validate(Graph<Signature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll();
            var result = RuleResult.Pass;
            foreach (var signature in signatures)
            {
                var signatureInfo = signature.SignerInfo;
                PublisherInformation info = null;
                foreach (var attribute in signatureInfo.SignedAttributes)
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
                    verboseWriter.LogSignatureMessage(signatureInfo, "Signature does not have any publisher information.");
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(info.Description))
                    {
                        result = RuleResult.Fail;
                        verboseWriter.LogSignatureMessage(signatureInfo, "Signature does not have an accompanying description.");
                    }

                    if (string.IsNullOrWhiteSpace(info.UrlLink))
                    {
                        result = RuleResult.Fail;
                        verboseWriter.LogSignatureMessage(signatureInfo, "Signature does not have an accompanying URL.");
                    }
                    else
                    {
                        Uri uri;
                        if (!Uri.TryCreate(info.UrlLink, UriKind.Absolute, out uri))
                        {
                            result = RuleResult.Fail;
                            verboseWriter.LogSignatureMessage(signatureInfo, "Signature's accompanying URL is not a valid URI.");
                        }
                    }
                }
            }
            return result;
        }
    }
}
