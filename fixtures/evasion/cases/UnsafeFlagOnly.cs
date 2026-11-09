// SPDX-License-Identifier: MIT
// H8 (policy 27): compiled with unsafe code enabled (see evasion.csproj) but with no unsafe construct.
// The flag alone is informational: the IL walk finds every pointer, address conversion and raw load or
// store, so this ordinary code is Limited access with nothing labelled (before H8: raw memory).
public static class UnsafeFlagOnly {
    public static int Sum(int[] xs) { int s = 0; foreach (var x in xs) s += x; return s; }
}
