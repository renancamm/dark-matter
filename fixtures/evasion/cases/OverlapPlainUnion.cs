// SPDX-License-Identifier: MIT
// Control: unions of plain data only (a float over an int, a struct of two floats over a long, an enum
// over a byte, a framework vector over an array of ints' worth of bytes). Reading the bits of one as
// the other reaches no memory. Expected: Limited access, no labels.
using System.Numerics;
using System.Runtime.InteropServices;

public struct PlainPair { public float X; public float Y; }
public enum PlainKind : byte { None, Some }

[StructLayout(LayoutKind.Explicit)]
public struct PlainUnion {
    [FieldOffset(0)] public float Single;
    [FieldOffset(0)] public int Bits;
    [FieldOffset(0)] public PlainPair Pair;
    [FieldOffset(0)] public long Wide;
    [FieldOffset(0)] public PlainKind Kind;
    [FieldOffset(0)] public Vector4 Vector;
    [FieldOffset(16)] public object Tag;
}

public static class OverlapPlainUnionCase {
    public static long Run(float f) {
        var u = new PlainUnion { Single = f, Tag = null };
        return u.Bits + u.Wide + (long)u.Kind + (long)u.Pair.Y + (long)u.Vector.W;
    }
}
