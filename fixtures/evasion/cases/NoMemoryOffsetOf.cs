// SPDX-License-Identifier: MIT
// H8 (policy 27): Marshal.OffsetOf is a layout query (Type, string and the generic form): it touches no
// memory. Limited access, nothing labelled (before H8: raw memory, through the Marshal:: rule).
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)] public struct OffsetPair { public int A; public long B; }

public static class NoMemoryOffsetOf {
    public static long Offsets() => (long)Marshal.OffsetOf(typeof(OffsetPair), "B") + (long)Marshal.OffsetOf<OffsetPair>("A");
}
