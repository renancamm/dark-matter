// SPDX-License-Identifier: MIT
// C2 near-miss: MemoryMarshal.AsBytes over a struct whose nested struct holds a string. The type is not plain
// data (the runtime throws for it at run time; the check does not rely on that), so this stays "Reads or
// writes memory directly" (Broad access).
using System;
using System.Runtime.InteropServices;

public struct Inner { public int N; public string S; }
public struct Hidden { public float F; public Inner I; }

public static class MemoryMarshalHidden {
    public static int Bytes(Span<Hidden> s) => MemoryMarshal.AsBytes(s).Length;
}
