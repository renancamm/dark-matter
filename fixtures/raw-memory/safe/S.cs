// SPDX-License-Identifier: MIT
// Ordinary C# that the compiler lowers to Unsafe and MemoryMarshal calls in generated helpers.
// None of it is raw memory access: the assembly must stay in Limited access.
using System;
using System.Runtime.CompilerServices;

[InlineArray(4)] public struct Buffer4 { int _element; }

public class SafeSpans {
    public static int CollectionExpression(int a, int b, int c) { ReadOnlySpan<int> xs = [a, b, c]; return xs[0] + xs[2]; }
    public static string ParamsSpan(string a, string b) => string.Concat(a, b, a, b, a);
    public static int Utf8Literal() => "hello"u8.Length;
    public static int StackallocSpan(int n) { Span<int> s = stackalloc int[8]; s[0] = n; return s[0]; }
    public static ReadOnlySpan<byte> StaticData => new byte[] { 1, 2, 3 };
    public static int InlineArrayIndex(int i) { var b = new Buffer4(); b[0] = 1; b[i] = 2; return b[3]; }
    // Stores through ref and out parameters, ref locals and ref returns, including across a join.
    public static void ConditionalOut(bool c, out double x, out Pair p) { x = c ? 1 : 2; p = c ? new Pair(1, 2) : default; }
    public static int ConditionalRef(bool c, ref int a, ref int b) { ref int r = ref (c ? ref a : ref b); r = 1; return r; }
    public static ref int Third(int[] a) => ref a[2];
    public static void ThroughRefReturn(int[] a) { Third(a) = 7; }
    public static int StackallocVariable(int n) { Span<int> s = stackalloc int[n]; s[0] = 1; return s[0]; }
    public static int StackallocStruct() { Span<Pair> s = stackalloc Pair[5]; s[4] = new Pair(1, 2); return s[4].A; }
    // Spans over constant data constructed in place (call instance .ctor on the local's address).
    public static int InPlaceConstants(int i) { ReadOnlySpan<byte> x = [1, 2, 3, 4, 5, 6, 7, 8, 9]; return x[i]; }
    public static int InPlaceUtf8(bool c) { ReadOnlySpan<byte> x; if (c) x = "abcdefgh"u8; else x = "xy"u8; return x.Length; }
}

public readonly struct Pair(int a, int b) {
    public int A { get; } = a;
    public int B { get; } = b;
}
