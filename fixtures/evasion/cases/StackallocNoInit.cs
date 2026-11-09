// SPDX-License-Identifier: MIT
// H8 review: the Span<byte> over stackalloc byte[n] of StackallocBytes, in a method marked [SkipLocalsInit].
// The buffer is not cleared, so the span reads whatever the stack held before. Full access, "Reads or
// writes memory directly" (the only evidence: the stackalloc without localsinit).
using System;
using System.Runtime.CompilerServices;

public static class StackallocNoInit {
    [SkipLocalsInit]
    public static int Bytes(int n) { Span<byte> s = stackalloc byte[n]; return s.Length; }
}
