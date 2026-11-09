// SPDX-License-Identifier: MIT
// C2 (policy 34): MemoryMarshal.AsBytes, Cast, Read, Write (and TryRead/TryWrite) with every type argument
// plain data: primitives, an enum, and structs of those nested in each other. The runtime refuses a type
// argument that holds a reference, bounds the result to the span's own bytes, and the result is a
// bounds-checked span or a value, so with plain types they reach only the bytes of the span they are
// given. Limited access, nothing labelled (before: "Reads or writes memory directly").
using System;
using System.Runtime.InteropServices;

public readonly struct Pair { public readonly int A; public readonly int B; public Pair(int a, int b) { A = a; B = b; } }
public enum Hue { Red, Green, Blue }
public struct Nested { public Pair P; public Hue H; public float F; public DateTime When; }

public static class MemoryMarshalPlain {
    public static int AsBytes(Span<int> s) => MemoryMarshal.AsBytes(s).Length;
    public static int AsBytesNested(ReadOnlySpan<Nested> s) => MemoryMarshal.AsBytes(s).Length;
    public static int Cast(Span<int> s) => MemoryMarshal.Cast<int, short>(s).Length;
    public static int CastStruct(ReadOnlySpan<byte> s) => MemoryMarshal.Cast<byte, Pair>(s).Length;
    public static int Read(ReadOnlySpan<byte> b) => MemoryMarshal.Read<int>(b);
    public static Nested ReadNested(ReadOnlySpan<byte> b) => MemoryMarshal.Read<Nested>(b);
    public static void Write(Span<byte> b, Pair p) => MemoryMarshal.Write(b, in p);
    public static bool TryRead(ReadOnlySpan<byte> b, out Hue h) => MemoryMarshal.TryRead(b, out h);
    public static bool TryWrite(Span<byte> b, long v) => MemoryMarshal.TryWrite(b, in v);
}
