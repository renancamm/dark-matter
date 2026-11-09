// SPDX-License-Identifier: MIT
// Pointer code: the check cannot follow what it reads or writes. Broad access.
public class Pointers {
    public static unsafe void Reinterpret(int x) { *(long*)&x = 5; }
    public static unsafe int Fixed(int[] a) { fixed (int* p = a) return p[1]; }
    public static unsafe byte First(System.IntPtr p) => new System.ReadOnlySpan<byte>(p.ToPointer(), 1)[0];
}
