// SPDX-License-Identifier: MIT
// C4, still flagged: a stackalloc initializer of struct elements. The compiler sizes the buffer with sizeof
// (a counted buffer, not a constant byte size) and stores each element with stobj at offsets built from
// sizeof, which the offset proof does not cover (README, Known gaps). "Reads or writes memory directly"
// (Broad access), before and after.
using System;

public readonly struct Pair { public readonly int A; public readonly int B; public Pair(int a, int b) { A = a; B = b; } }

public static class StackallocInitStruct {
    public static int Pairs() { Span<Pair> s = stackalloc Pair[] { new Pair(1, 2), new Pair(3, 4) }; return s[1].A; }
}
