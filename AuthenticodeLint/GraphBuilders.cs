using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace AuthenticodeLint
{
    public static class GraphBuilder
    {
        public static Graph<Signature> ExplodeGraph(byte[] entireMessage, string nestedOidType) => WalkGraph(new List<byte[]> { entireMessage }, nestedOidType);

        public static Graph<ISignature> WalkCounterSignatures(Signature signature) => WalkCounterSignatures(signature.SignerInfo.UnsignedAttributes);

        private static Graph<ISignature> WalkCounterSignatures(CryptographicAttributeObjectCollection attributes)
        {
            var graphItems = new List<GraphItem<ISignature>>();
            foreach (var attribute in attributes)
            {
                foreach(var value in attribute.Values)
                {
                    ISignature signature;
                    if (attribute.Oid.Value == KnownOids.AuthenticodeCounterSignature)
                    {
                        signature = new AuthenticodeSignature(value);
                    }
                    else if (attribute.Oid.Value == KnownOids.Rfc3161CounterSignature)
                    {
                        signature = new Rfc3161Signature(value);
                    }
                    else
                    {
                        continue;
                    }
                    var childAttributes = new CryptographicAttributeObjectCollection();
                    foreach(var childAttribute in signature.UnsignedAttributes)
                    {
                        childAttributes.Add(childAttribute);
                    }
                    graphItems.Add(new GraphItem<ISignature>(signature, WalkCounterSignatures(childAttributes)));
                }
            }
            return new Graph<ISignature>(graphItems);
        }

        private static Graph<Signature> WalkGraph(IList<byte[]> cmsData, string nestedOidType)
        {
            var graphItems = new List<GraphItem<Signature>>();
            foreach (var data in cmsData)
            {
                var cms = new SignedCms();
                cms.Decode(data);
                foreach (var signer in cms.SignerInfos)
                {
                    var childCms = new List<byte[]>();
                    foreach (var attribute in signer.UnsignedAttributes)
                    {
                        if (attribute.Oid.Value == nestedOidType)
                        {
                            foreach (var value in attribute.Values)
                            {
                                childCms.Add(value.RawData);
                            }
                        }
                    }
                    graphItems.Add(new GraphItem<Signature>(new Signature(signer, cms.Certificates), WalkGraph(childCms, nestedOidType)));
                }
            }
            return new Graph<Signature>(graphItems);
        }
    }
}
