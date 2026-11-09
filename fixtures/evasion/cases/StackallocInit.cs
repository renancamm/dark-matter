// SPDX-License-Identifier: MIT
// C4 (policy 34): the stores of stackalloc initializers, in every shape the C# compiler emits: element stores
// at constant offsets (stind), a block fill of zeros (initblk), a block copy from constant data by its
// address (cpblk after ldsflda) and from a span over it (cpblk after RuntimeHelpers.CreateSpan and the
// span's indexer), and a mixed initializer with a run-time value. Each store's offset and size, or the
// copy's length, is checked against the buffer's constant size. Limited access, nothing labelled (before:
// "Reads or writes memory directly").
using System;

public enum Hue { Red, Green, Blue }

public static class StackallocInit {
    public static int Three() { Span<int> s = stackalloc int[] { 1, 2, 3 }; return s[2]; }
    public static int Many() { Span<int> s = stackalloc int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }; return s[2]; }
    public static int Zeros() { Span<int> s = stackalloc int[] { 0, 0, 0, 0, 0, 0, 0, 0 }; return s[2]; }
    public static byte Bytes() { Span<byte> s = stackalloc byte[] { 1, 2, 3, 4, 5, 6 }; return s[2]; }
    public static int Mixed(int a) { Span<int> s = stackalloc int[] { a, 2, 3 }; return s[2]; }
    public static long Longs() { Span<long> s = stackalloc long[] { 1, 2 }; return s[1]; }
    public static double Doubles(double d) { Span<double> s = stackalloc double[] { d, 2.5, 3.5 }; return s[2]; }
    public static int Enums() { Span<Hue> s = stackalloc Hue[] { Hue.Red, Hue.Blue }; return (int)s[1]; }
    public static short Shorts() { ReadOnlySpan<short> s = stackalloc short[] { 1, 2, 3, 4, 5, 6, 7 }; return s[6]; }
}
