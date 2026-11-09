// SPDX-License-Identifier: MIT
// C3 near-miss: an explicit-layout union over a generic framework struct (KeyValuePair<int, int>). A generic
// instantiation is not laid out, plain or not, so the overlap stays "Reads or writes memory directly" (Broad
// access), fail closed.
using System.Collections.Generic;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Explicit)]
public struct PairUnion {
    [FieldOffset(0)] public KeyValuePair<int, int> Pair;
    [FieldOffset(0)] public long Bits;
}

public static class UnionFrameworkGeneric {
    public static long Bits(PairUnion u) => u.Bits;
}
