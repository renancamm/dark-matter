// SPDX-License-Identifier: MIT
// H8 (policy 27): stackalloc of 1-byte elements with a variable count. The compiler leaves out the
// multiply (the byte count is the element count), and the span's length is the same local: it is a
// bounds-checked span, not raw memory. Limited access, nothing labelled (before H8: raw memory).
using System;

public static class StackallocBytes {
    public static int Bytes(int n) { Span<byte> s = stackalloc byte[n]; s.Fill(1); return s.Length; }
    public static bool Flags(int n) { Span<bool> s = stackalloc bool[n]; s[0] = true; return s[0]; }
    public static int Signed(int n) { Span<sbyte> s = stackalloc sbyte[n]; s[n - 1] = -1; return s[n - 1]; }
}
