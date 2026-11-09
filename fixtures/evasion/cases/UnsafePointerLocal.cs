// SPDX-License-Identifier: MIT
// H8 negative: the same unsafe compile flag with a pointer local. The pointer is raw memory, whatever
// the flag says: Full access, "Reads or writes memory directly". Pinned clears the pinned reference with a
// constant 0 at the end of the fixed block, which counts as null since H8 (the pointer itself still counts).
public static class UnsafePointerLocal {
    public static unsafe int First(int[] xs) { fixed (int* p = xs) { int* q = p; return *q; } }
    public static unsafe int Pinned(ref int x) { int r; fixed (int* p = &x) r = *p; return r + 1; }
}
