// SPDX-License-Identifier: MIT
// Probe case: an inline array of four references at offset 0 of an explicit-layout struct, and a
// string at offset 16, where the array's third element lies. The runtime accepts the layout (only
// references overlap) and an object stored as element 2 is then read as a string: a type confusion
// with no API call. Laid out from its one field, the array would seem to end at 8.
// Expected: Broad access, raw memory only.
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[InlineArray(4)]
public struct OverlapInlineRefs { public object Element; }

[StructLayout(LayoutKind.Explicit)]
public struct OverlapInlineUnion {
    [FieldOffset(0)] public OverlapInlineRefs Refs;
    [FieldOffset(16)] public string Text;
}

public static class OverlapInlineArrayCase {
    public static string Run(object o) {
        var u = new OverlapInlineUnion();
        u.Refs[2] = o;
        return u.Text;
    }
}
