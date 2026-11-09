// SPDX-License-Identifier: MIT
// C2 near-miss: MemoryMarshal.Cast to a native integer. The runtime allows it (no reference), but a native int
// holds addresses as often as numbers and is not plain data to the check, so this stays "Reads or writes
// memory directly" (Broad access).
using System;
using System.Runtime.InteropServices;

public static class MemoryMarshalNativeInt {
    public static int Cast(Span<byte> s) => MemoryMarshal.Cast<byte, IntPtr>(s).Length;
}
