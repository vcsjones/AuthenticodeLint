using AuthenticodeExaminer;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public static class SignatureExtensions
    {
        public static IEnumerable<ICmsSignature> VisitAll(this ICmsSignature signature, SignatureKind kind, bool deep = false)
        {
            foreach (var nested in signature.GetNestedSignatures())
            {
                if ((nested.Kind & kind) > 0)
                {
                    yield return nested;
                    foreach (var nestVisit in nested.VisitAll(kind, deep))
                    {
                        yield return nestVisit;
                    }
                }
                else if (deep)
                {
                    foreach (var nestVisit in nested.VisitAll(kind, deep))
                    {
                        yield return nestVisit;
                    }
                }
            }
        }

        public static IEnumerable<ICmsSignature> VisitAll(this IReadOnlyList<ICmsSignature> signatures, SignatureKind kind, bool deep = false)
        {
            foreach (var signature in signatures)
            {
                if ((signature.Kind & kind) > 0)
                {
                    yield return signature;
                }
                foreach (var nested in VisitAll(signature, kind, deep))
                {
                    yield return nested;
                }
            }
        }
    }
}
