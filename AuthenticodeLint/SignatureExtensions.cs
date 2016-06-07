using System;
using System.Collections.Generic;

namespace AuthenticodeLint
{
    public static class SignatureExtensions
    {
        public static IEnumerable<ISignature> VisitAll(this ISignature signature, SignatureKind kind)
        {
            if ((signature.Kind & kind) > 0)
            {
                yield return signature;
            }
            foreach (var nested in signature.GetNestedSignatures())
            {
                if ((nested.Kind & kind) > 0)
                {
                    yield return nested;
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
                foreach (var nested in signature.GetNestedSignatures())
                {
                    if ((nested.Kind & kind) > 0)
                    {
                        yield return nested;
                    }
                }
            }
        }
    }


    [Flags]
    public enum SignatureKind
    {
        NestedSignature = 0x1,
        Signature = 0x2,
        AuthenticodeSignature = 0x4,
        Rfc3161Signature = 0x8,
        AnySignature = NestedSignature | Signature,
        AnyCounterSignature = AuthenticodeSignature | Rfc3161Signature,
        Any = AnySignature | AnyCounterSignature
    }
}
