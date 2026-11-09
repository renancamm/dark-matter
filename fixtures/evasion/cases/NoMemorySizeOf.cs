// SPDX-License-Identifier: MIT
// H8 (policy 27): Unsafe.SizeOf is a layout query and Unsafe.IsNullRef only compares a reference with
// null: neither touches memory. Limited access, nothing labelled (before H8: raw memory).
using System.Runtime.CompilerServices;

public struct SizedPair { public int A; public long B; }

public static class NoMemorySizeOf {
    public static int Size() => Unsafe.SizeOf<SizedPair>();
    public static bool Missing(ref int x) => Unsafe.IsNullRef(ref x);
}
