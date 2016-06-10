using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthenticodeLint
{
    public static class SignatureExtensions
    {
        public static IEnumerable<ISignature> VisitAll(this ISignature signature, SignatureKind kind)
        {
            foreach (var nested in signature.GetNestedSignatures())
            {
                if ((nested.Kind & kind) > 0)
                {
                    yield return nested;
                    foreach(var nestVisit in nested.VisitAll(kind))
                    {
                        yield return nestVisit;
                    }
                }
                else if ((kind & SignatureKind.Deep) == SignatureKind.Deep)
                {
                    foreach (var nestVisit in nested.VisitAll(kind))
                    {
                        yield return nestVisit;
                    }
                }
            }
        }

        public static IEnumerable<ISignature> VisitAll(this IReadOnlyList<ISignature> signatures, SignatureKind kind)
        {
            foreach (var signature in signatures)
            {
                if ((signature.Kind & kind) > 0)
                {
                    yield return signature;
                }
                foreach (var nested in VisitAll(signature, kind))
                {
                    yield return nested;
                }
            }
        }
    }


    [Flags]
    public enum SignatureKind
    {
        NestedSignature = 0x1,
        Signature = 0x2,
        AuthenticodeTimestamp = 0x4,
        Rfc3161Timestamp = 0x8,
        AnySignature = NestedSignature | Signature,
        AnyCounterSignature = AuthenticodeTimestamp | Rfc3161Timestamp,
        Any = AnySignature | AnyCounterSignature,
        Deep = 0x1000
    }
}
