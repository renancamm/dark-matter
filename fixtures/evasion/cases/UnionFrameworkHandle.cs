// SPDX-License-Identifier: MIT
// C3 near-miss: an explicit-layout union over a framework struct that holds a native integer (GCHandle wraps
// an IntPtr). The framework's metadata shows it is not plain data, so the overlap stays "Reads or writes
// memory directly" (Broad access): the check never uses a framework layout to bound a reference.
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Explicit)]
public struct HandleUnion {
    [FieldOffset(0)] public GCHandle Handle;
    [FieldOffset(0)] public long Bits;
}

public static class UnionFrameworkHandle {
    public static long Bits(HandleUnion u) => u.Bits;
}
