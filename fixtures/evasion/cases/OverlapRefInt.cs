// SPDX-License-Identifier: MIT
// Probe case: a reference field over an integer and over a native integer, in an explicit-layout
// class. The runtime rejects such a type when it loads it; the check counts it as raw memory all the
// same, from metadata alone. Expected: Full access, raw memory only.
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Explicit)]
public sealed class OverlapRefIntUnion {
    [FieldOffset(0)] public object Target;
    [FieldOffset(0)] public long Bits;
    [FieldOffset(0)] public IntPtr Address;
}

public static class OverlapRefIntCase {
    public static long Run(object o) {
        var u = new OverlapRefIntUnion { Target = o };
        return u.Bits + (long)u.Address;
    }
}
