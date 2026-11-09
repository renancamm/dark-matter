// SPDX-License-Identifier: MIT
// Probe case: two reference fields at the same offset of an explicit-layout struct. Writing one and
// reading the other treats a string as a Box, a type confusion with no API call.
// Expected: Broad access, raw memory only.
using System.Runtime.InteropServices;

public sealed class OverlapBox { public long Value; }

[StructLayout(LayoutKind.Explicit)]
public struct OverlapRefsUnion {
    [FieldOffset(0)] public object Any;
    [FieldOffset(0)] public OverlapBox AsBox;
}

public static class OverlapRefsCase {
    public static long Run(string s) {
        var u = new OverlapRefsUnion { Any = s };
        return u.AsBox.Value;
    }
}
